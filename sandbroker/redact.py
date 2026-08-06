"""Remove secret values from anything on its way back to the caller.

THE ONE GUARANTEE
-----------------
Any byte sequence this process resolved from the vault is stripped out of the
data returned to the agent. Nothing else. This is a literal-match filter over
each secret and its common transport encodings.

WHAT THIS IS NOT
----------------
It is not a secret detector. It does not look for things that merely resemble
credentials, it does not score entropy, and it has no opinion about values it
was never given. A token minted DURING the call (an OAuth exchange, a session
cookie handed back by the API) is unknown to this module and will pass through
untouched. That residual risk is accepted by design, and it is exactly what the
agent's "if you ever see a live token, raise the alarm" rule is there to cover.

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
import html
import json
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
