"""Remove secret values from anything on its way back to the caller.

Two filters live here and they make deliberately different promises. Keep them
apart: the value of the first is that it never guesses, and the value of the
second is that it does.

TIER 1, `Redactor` -- THE ONE GUARANTEE
---------------------------------------
Any byte sequence this process resolved from the vault is stripped out of the
data returned to the agent. Nothing else. This is a literal-match filter over
each secret and its common transport encodings. It is not a secret detector: it
has no opinion about values it was never given, and it never fires on something
that merely resembles a credential. Marker: `[redacted:NAME]`.

TIER 2, `HeuristicRedactor` -- BEST EFFORT, NO GUARANTEE
--------------------------------------------------------
A token minted DURING the call -- an OAuth exchange, a session cookie, a
create-tunnel response body -- was never injected, so Tier 1 cannot know it and
it used to pass through untouched. That was an accepted risk while minting was
an occasional accident. It stops being acceptable for a workload whose whole job
is minting credentials, such as a rotation run, where the rare case becomes the
every-call case.

Tier 2 therefore does guess: it looks for credential-SHAPED strings by prefix
and by entropy. It will miss things and it will fire on innocent ones. Marker:
`[likely-credential:sha256=...]`, deliberately different from Tier 1's, so a
reader can always tell which filter acted and never mistakes a heuristic hit for
the guarantee. A Tier 2 hit still means `report_leak`: it is evidence a live
credential reached the boundary, not proof it was contained.

WHY ENCODINGS
-------------
A secret that goes out as a bearer token routinely comes back quoted, escaped,
or wrapped: percent-encoded in a redirect URL, JSON-escaped in an error body,
base64'd inside an Authorization header the server echoed. Those are still
literal occurrences of the same secret, just spelled differently, so matching
them is not heuristics creeping back in -- it is the same exact-match rule
applied to the same bytes after a reversible transform.
"""

import base64
import binascii
import hashlib
import html
import json
import math
import re
import urllib.parse

# A base64 run has to be at least this long to be worth a decode attempt, and no
# longer than the cap, so a multi-megabyte attachment cannot turn scrubbing into
# a CPU sink. Both numbers are about cost, not safety.
_B64_MIN = 16
_B64_MAX = 8192
_B64_BUDGET = 512

_B64_RUN = re.compile(rb"[A-Za-z0-9+/=_-]{%d,%d}" % (_B64_MIN, _B64_MAX))


def _encodings(value):
    """Every spelling of `value` we know how to recognise, longest first.

    Longest-first matters: percent-encoding a value that contains no reserved
    characters yields the value itself, and several transforms collide on short
    ASCII. Replacing the longest form first stops a shorter form from carving up
    a longer one and leaving a fragment behind.
    """
    raw = value.encode("utf-8", "surrogatepass")
    forms = {value}

    # URL / query-string
    forms.add(urllib.parse.quote(value, safe=""))
    forms.add(urllib.parse.quote_plus(value))

    # JSON string body, i.e. what json.dumps would embed
    forms.add(json.dumps(value)[1:-1])

    # HTML / XML entity escaping
    forms.add(html.escape(value, quote=True))

    # Hex, both cases -- some APIs echo binary credentials this way
    forms.add(raw.hex())
    forms.add(raw.hex().upper())

    # base64, standard and URL-safe, padded and stripped
    for enc in (base64.b64encode, base64.urlsafe_b64encode):
        b64 = enc(raw).decode("ascii")
        forms.add(b64)
        forms.add(b64.rstrip("="))

    forms.discard("")
    return sorted(forms, key=len, reverse=True)


class Redactor:
    """Holds the secrets resolved for one `run` and scrubs output of them.

    Construct it with {env_var_name: secret_value}. The placeholder names the
    variable rather than using a generic marker so the agent can tell WHICH
    credential landed where, which is real debugging signal and gives away
    nothing: it already chose that name.
    """

    def __init__(self, secrets):
        self._count = 0
        self._forms = []          # [(encoded_form, placeholder)]
        self._raw_bytes = []      # [(utf8_bytes, placeholder_bytes)]
        self._values = []         # for the base64-wrapper pass

        # Longest secret first, for the same reason encodings are sorted:
        # one secret can be a prefix of another (a token and "token:secret").
        for name in sorted(secrets, key=lambda n: len(secrets[n]), reverse=True):
            value = secrets[name]
            if not value:
                continue
            placeholder = "[redacted:%s]" % name
            self._values.append(value)
            self._raw_bytes.append(
                (value.encode("utf-8", "surrogatepass"), placeholder.encode("ascii"))
            )
            for form in _encodings(value):
                self._forms.append((form, placeholder))

        self._forms.sort(key=lambda pair: len(pair[0]), reverse=True)

    @property
    def hits(self):
        """How many substitutions were made. Non-zero is normal, not alarming:
        a verbose HTTP client echoing its own Authorization header is the usual
        cause."""
        return self._count

    def scrub_bytes(self, data):
        """Scrub raw bytes before decoding.

        Decoding with errors="replace" can mangle a secret into something the
        string pass would no longer recognise, so the exact-match pass runs
        first, while the bytes are still intact.
        """
        for needle, placeholder in self._raw_bytes:
            if needle in data:
                self._count += data.count(needle)
                data = data.replace(needle, placeholder)
        return self._scrub_b64_wrappers(data)

    def scrub(self, text):
        """Scrub a decoded string across every known encoding of every secret."""
        for form, placeholder in self._forms:
            if form in text:
                self._count += text.count(form)
                text = text.replace(form, placeholder)
        return text

    def _scrub_b64_wrappers(self, data):
        """Catch a secret hiding one base64 layer down.

        `Authorization: Basic base64("user:password")` is the case that matters:
        the password is genuinely present but no encoding of the password alone
        appears in the blob, because it was concatenated before encoding. So
        decode each base64-looking run and, if the plaintext contains a secret,
        replace the whole run -- the wrapper is unsalvageable once part of it is
        secret.

        Still an exact match on the secret, just after one reversible decode.
        """
        if not self._values:
            return data
        budget = _B64_BUDGET
        out = data
        for match in _B64_RUN.finditer(data):
            if budget <= 0:
                break
            budget -= 1
            run = match.group(0)
            try:
                # validate=False: real-world headers wrap and pad sloppily.
                decoded = base64.b64decode(run + b"===", validate=False)
            except (binascii.Error, ValueError):
                continue
            try:
                plain = decoded.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if any(value in plain for value in self._values):
                self._count += 1
                out = out.replace(run, b"[redacted:base64]")
        return out

    def clean(self, data):
        """Full pipeline for one captured stream: bytes pass, decode, string pass."""
        scrubbed = self.scrub_bytes(data)
        return self.scrub(scrubbed.decode("utf-8", "replace"))


# Vendor prefixes that are credential-shaped on sight. These are near-zero false
# positive: no ordinary output contains "sk-ant-api03-" followed by 90 random
# characters. "eyJ" covers both JWTs and cloudflared connector tokens, which are
# base64 of a JSON object and so begin the same way -- that is the exact shape
# that leaked in alert 1786313954.
_PREFIXED = re.compile(
    r"\b("
    r"sk-ant-[A-Za-z0-9_\-]{20,}"
    r"|sk-proj-[A-Za-z0-9_\-]{20,}"
    r"|sk-[A-Za-z0-9]{32,}"
    r"|secret-token:[A-Za-z0-9_\-]{16,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|glpat-[A-Za-z0-9_\-]{16,}"
    r"|xox[baprs]-[A-Za-z0-9\-]{16,}"
    r"|xapp-[A-Za-z0-9\-]{16,}"
    r"|AIza[A-Za-z0-9_\-]{30,}"
    r"|A[KS]IA[A-Z0-9]{16}"
    r"|dop_v1_[a-f0-9]{60,}"
    r"|shpat_[a-f0-9]{30,}"
    r"|whsec_[A-Za-z0-9]{20,}"
    r"|hf_[A-Za-z0-9]{30,}"
    r"|eyJ[A-Za-z0-9_\-]{10,}"
    r")"
)

# Generic shapes, only consulted when entropy scanning is switched on.
_B64ISH = re.compile(r"[A-Za-z0-9+/_\-]{32,}={0,2}")
_HEXISH = re.compile(r"\b[0-9a-fA-F]{40,}\b")

# Pure hex of exactly these lengths is overwhelmingly a git object id or a
# sha256 digest, not a credential. Redacting those makes ordinary output
# unreadable for no security gain. This is a KNOWN HOLE, accepted knowingly: a
# credential that happens to be exactly 40 or 64 hex characters slips past the
# generic pass. It is documented rather than silently tuned away.
_BENIGN_HEX_LENGTHS = frozenset({40, 64})

_ENTROPY_FLOOR = 3.2


def fingerprint(text):
    """Short, stable, printable identifier for a value.

    This is what makes verification possible without disclosure: the same secret
    fingerprints identically wherever it is checked, so the vault copy, the copy
    in a Nomad variable and the one a live service presents can be confirmed
    identical without any of them being shown.
    """
    digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
    return digest[:12]


def _shannon_bits_per_char(text):
    """Shannon entropy in bits per character.

    Prose sits near 4.0 but over a small alphabet; the discriminator that
    actually works here is that structured identifiers (repeated separators,
    dictionary words, long runs of one character) fall well below a random
    string drawn from the same alphabet.
    """
    if not text:
        return 0.0
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    bits = 0.0
    for count in counts.values():
        p = count / total
        bits -= p * math.log2(p)
    return bits


class HeuristicRedactor:
    """Tier 2. Finds credential-shaped strings nobody declared.

    Two independent passes:

    `prefix`   vendor-branded tokens. Always on, because the false positive rate
               is negligible and these are the highest-value things to catch.
    `entropy`  generic long random-looking runs. OFF by default, because shape
               alone cannot separate a 40-hex secret from a git SHA, so leaving
               it on would redact commit ids in ordinary output. Rotation and
               browser flows switch it on, where mangled output is a fair price
               and an unnoticed minted token is not.

    Replacements carry a truncated sha256 of the matched text. That is not
    decoration: it lets two sides confirm they are talking about the same
    credential -- the value stored in the vault, the one in a Nomad variable,
    the one a live service presents -- without anyone seeing it.
    """

    def __init__(self, entropy_scan=False, entropy_floor=_ENTROPY_FLOOR):
        self.entropy_scan = entropy_scan
        self.entropy_floor = entropy_floor
        self._count = 0

    @property
    def hits(self):
        """How many substitutions were made. Unlike Tier 1, any non-zero value
        here is worth reporting: it means something credential-shaped that the
        broker never injected reached the boundary."""
        return self._count

    fingerprint = staticmethod(fingerprint)

    def _placeholder(self, matched):
        return "[likely-credential:sha256=%s,len=%d]" % (
            self.fingerprint(matched),
            len(matched),
        )

    def _looks_random(self, candidate):
        if candidate.isdigit():
            return False
        is_hex = all(c in "0123456789abcdefABCDEF" for c in candidate)
        if is_hex and len(candidate) in _BENIGN_HEX_LENGTHS:
            return False
        return _shannon_bits_per_char(candidate) >= self.entropy_floor

    def scrub(self, text):
        """Replace credential-shaped runs. Returns the scrubbed string."""
        text = self._replace(text, _PREFIXED, lambda _: True)
        if self.entropy_scan:
            for pattern in (_HEXISH, _B64ISH):
                text = self._replace(text, pattern, self._looks_random)
        return text

    def _replace(self, text, pattern, predicate):
        def swap(match):
            matched = match.group(0)
            if not predicate(matched):
                return matched
            self._count += 1
            return self._placeholder(matched)

        return pattern.sub(swap, text)
