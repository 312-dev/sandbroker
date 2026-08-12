"""Config policy and reference parsing."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbroker.config import Config, ConfigError  # noqa: E402
from sandbroker.onepassword import Vault, VaultError  # noqa: E402

VAULTS = {"Dev": {"vault": "Acme - Dev", "token": "Dev", "port": 8770}}


class TestBindPolicy(unittest.TestCase):
    """The HTTP surface has no authentication by design, so reachability IS the
    authorisation. The daemon must refuse to sit anywhere it could be routed to
    from outside the tailnet."""

    def test_no_bind_means_socket_only(self):
        self.assertIsNone(Config({"vaults": VAULTS}).bind_address())

    def test_loopback_allowed(self):
        cfg = Config({"vaults": VAULTS, "bind": "127.0.0.1"})
        self.assertEqual("127.0.0.1", cfg.bind_address())

    def test_tailnet_allowed(self):
        for addr in ("100.64.0.1", "100.85.12.34", "100.127.255.254"):
            cfg = Config({"vaults": VAULTS, "bind": addr})
            self.assertEqual(addr, cfg.bind_address())

    def test_public_and_lan_refused(self):
        # 203.0.113.0/24 and 198.51.100.0/24 are RFC 5737 documentation ranges,
        # so nothing here is a real host anyone could be pointed at.
        for addr in ("0.0.0.0", "192.168.1.10", "10.0.0.5", "203.0.113.10",
                     "198.51.100.5", "100.200.1.1", "100.5.5.5", ""):
            cfg = Config({"vaults": VAULTS, "bind": addr})
            if addr == "":
                self.assertIsNone(cfg.bind_address())
                continue
            with self.assertRaises(ConfigError, msg="should refuse %s" % addr):
                cfg.bind_address()


class TestConfigValidation(unittest.TestCase):
    def test_no_vaults_is_fatal(self):
        with self.assertRaises(ConfigError):
            Config({"vaults": {}})

    def test_vault_needs_a_real_name_and_token(self):
        with self.assertRaises(ConfigError):
            Config({"vaults": {"Dev": {"token": "Dev"}}})
        with self.assertRaises(ConfigError):
            Config({"vaults": {"Dev": {"vault": "Real"}}})

    def test_unknown_vault_lists_the_known_ones(self):
        cfg = Config({"vaults": VAULTS})
        with self.assertRaises(ConfigError) as ctx:
            cfg.vault("Nope")
        self.assertIn("Dev", str(ctx.exception))

    def test_paths_are_derived_from_the_alias(self):
        cfg = Config({"vaults": VAULTS, "tokens_dir": "/t", "socket_dir": "/r"})
        self.assertEqual("/t/Dev.token", cfg.token_file("Dev"))
        self.assertEqual("/r/dev.sock", cfg.socket_path("Dev"))


class TestRefParsing(unittest.TestCase):
    def setUp(self):
        self.vault = Vault("Dev", "Acme - Dev", "/nonexistent", "/bin/true")

    def test_fully_qualified(self):
        self.assertEqual(("mercury", "credential"),
                         self.vault.parse_ref("op://Dev/mercury/credential"))

    def test_item_and_field_shorthand(self):
        self.assertEqual(("mercury", "token"),
                         self.vault.parse_ref("mercury/token"))

    def test_bare_item_defaults_the_field(self):
        self.assertEqual(("mercury", "credential"),
                         self.vault.parse_ref("mercury"))

    def test_real_vault_name_also_accepted(self):
        self.assertEqual(("m", "f"),
                         self.vault.parse_ref("op://Acme - Dev/m/f"))

    def test_another_vault_is_refused_with_a_pointer(self):
        """Cross-vault refs are the isolation boundary: this process holds only
        one token, so it must not pretend it could serve another vault."""
        with self.assertRaises(VaultError) as ctx:
            self.vault.parse_ref("op://Production/thing/credential")
        self.assertIn("Production", str(ctx.exception))

    def test_fields_with_spaces_and_slashes(self):
        self.assertEqual(("my item", "API Key/v2"),
                         self.vault.parse_ref("op://Dev/my item/API Key/v2"))

    def test_empty_is_refused(self):
        for bad in ("", "   ", "op://", "op://Dev"):
            with self.assertRaises(VaultError):
                self.vault.parse_ref(bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
