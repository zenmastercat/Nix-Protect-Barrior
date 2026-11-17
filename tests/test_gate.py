"""Unit tests for the build gate rules (no Nix needed)."""
import importlib.util
import os
import pathlib
import sys
import unittest

TOOLS = pathlib.Path(os.environ.get("NPB_TOOLS", pathlib.Path(__file__).resolve().parent.parent / "tools"))
spec = importlib.util.spec_from_file_location("npb_check", TOOLS / "npb_check.py")
npb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(npb)


def lock(**nodes):
    n = {"root": {"inputs": {k: k for k in nodes}}}
    n.update({k: {"locked": v} for k, v in nodes.items()})
    return {"nodes": n, "root": "root", "version": 7}


GH = {"type": "github", "owner": "NixOS", "repo": "nixpkgs", "rev": "abc", "narHash": "sha256-x"}


def levels(rep, check=None):
    return [(i["level"], i["message"]) for i in rep.items if check is None or i["check"] == check]


class LockRules(unittest.TestCase):
    def test_identity_ignores_revision_and_case(self):
        a = npb.input_identity(GH)
        b = npb.input_identity(dict(GH, rev="def", owner="nixos"))
        self.assertEqual(a, b)
        self.assertEqual(a, "github:nixos/nixpkgs")

    def test_pinned_known_input_passes(self):
        rep = npb.Report()
        npb.check_lock(lock(nixpkgs=GH), {"github:nixos/nixpkgs"}, rep)
        self.assertFalse(rep.failed, levels(rep))

    def test_new_source_blocks(self):
        rep = npb.Report()
        evil = dict(GH, owner="evil-fork")
        npb.check_lock(lock(nixpkgs=evil), {"github:nixos/nixpkgs"}, rep)
        self.assertTrue(rep.failed)
        self.assertIn("never approved", " ".join(m for _, m in levels(rep)))

    def test_unpinned_blocks(self):
        rep = npb.Report()
        npb.check_lock(lock(x={"type": "github", "owner": "a", "repo": "b"}), None, rep)
        msgs = " ".join(m for _, m in levels(rep))
        self.assertTrue(rep.failed)
        self.assertIn("not pinned", msgs)
        self.assertIn("no pinned revision", msgs)

    def test_plain_http_blocks(self):
        rep = npb.Report()
        npb.check_lock(lock(x={"type": "tarball", "url": "http://example.org/x.tar.gz", "narHash": "sha256-y"}),
                       None, rep)
        self.assertTrue(rep.failed)

    def test_local_path_warns(self):
        rep = npb.Report()
        npb.check_lock(lock(x={"type": "path", "path": "/home/u/x", "narHash": "sha256-y"}), None, rep)
        self.assertFalse(rep.failed)
        self.assertEqual(levels(rep)[0][0], npb.WARN)


HARD = {"barrier": True, "buildEnable": True, "gateEnable": True, "gateAutoUpgrade": True,
        "sysctls": True, "restrictPtrace": True, "closeSsh": True, "dockerLocalOnly": True,
        "ollamaLocalOrigins": True, "verify": True, "autoRepair": True, "audit": True,
        "localTcp": [11434], "localUdp": [], "localTcpRanges": ["21115-21119"], "localUdpRanges": []}


def cfg(**kw):
    s = {"substituters": ["https://cache.nixos.org/"], "trusted-public-keys": ["k1"],
         "trusted-users": ["root"], "sandbox": True, "require-sigs": True, "accept-flake-config": False}
    s.update(kw.pop("settings", {}))
    h = dict(HARD)
    h.update(kw.pop("hardening", {}))
    c = {"settings": s, "insecure": [], "hardening": h, "extraOptions": kw.pop("extraOptions", "")}
    c.update(kw)
    return npb.apply_extra_options(c)


POLICY = {"allowedSubstituters": ["https://cache.nixos.org"], "trustedPublicKeys": ["k1"],
          "trustedUsers": ["root"], "hardening": HARD}


class ConfigRules(unittest.TestCase):
    def run_cfg(self, c, approved=None):
        rep = npb.Report()
        npb.check_config(c, POLICY, approved or {}, rep)
        return rep

    def test_clean_config_passes(self):
        self.assertFalse(self.run_cfg(cfg()).failed)

    def test_untrusted_cache_blocks(self):
        self.assertTrue(self.run_cfg(cfg(settings={"substituters": ["https://evil.example"]})).failed)

    def test_approved_cache_passes(self):
        c = cfg(settings={"substituters": ["https://ros.cachix.org"]})
        self.assertFalse(self.run_cfg(c, {"substituters": ["https://ros.cachix.org"]}).failed)

    def test_unknown_key_blocks(self):
        self.assertTrue(self.run_cfg(cfg(settings={"trusted-public-keys": ["k1", "fake"]})).failed)

    def test_trusted_user_blocks(self):
        self.assertTrue(self.run_cfg(cfg(settings={"trusted-users": ["root", "@wheel"]})).failed)

    def test_sandbox_off_blocks_even_if_approved(self):
        c = cfg(settings={"sandbox": "relaxed"})
        self.assertTrue(self.run_cfg(c, {"inputs": {}}).failed)

    def test_flake_config_blocks(self):
        self.assertTrue(self.run_cfg(cfg(settings={"accept-flake-config": True})).failed)

    def test_turning_barrier_off_blocks(self):
        self.assertTrue(self.run_cfg(cfg(hardening={"barrier": False})).failed)

    def test_turning_one_protection_off_blocks(self):
        for k in ("sysctls", "closeSsh", "audit", "verify", "gateAutoUpgrade", "dockerLocalOnly"):
            self.assertTrue(self.run_cfg(cfg(hardening={k: False})).failed, k)

    def test_removing_local_only_port_blocks(self):
        self.assertTrue(self.run_cfg(cfg(hardening={"localTcp": []})).failed)
        self.assertTrue(self.run_cfg(cfg(hardening={"localTcpRanges": []})).failed)

    def test_exactly_approved_weakening_passes(self):
        c = cfg(hardening={"sysctls": False})
        self.assertFalse(self.run_cfg(c, {"hardening": c["hardening"]}).failed)

    def test_extra_settings_are_checked(self):
        self.assertTrue(self.run_cfg(cfg(settings={"trusted-users": ["root", "lucas"]})).failed)

    def test_extra_options_cannot_add_trust(self):
        for line in ("extra-substituters = https://evil.example",
                     "trusted-public-keys = evil:AAAA",
                     "extra-trusted-users = lucas",
                     "sandbox = false",
                     "require-sigs = false",
                     "!include /home/lucas/nix.conf"):
            self.assertTrue(self.run_cfg(cfg(extraOptions=line)).failed, line)

    def test_harmless_extra_options_pass(self):
        self.assertFalse(self.run_cfg(cfg(extraOptions="keep-outputs = true\n# comment")).failed)

    def test_new_insecure_package_blocks_old_one_warns(self):
        rep = self.run_cfg(cfg(insecure=["electron-1"]), {"insecure": ["electron-1"]})
        self.assertFalse(rep.failed)
        self.assertTrue(self.run_cfg(cfg(insecure=["openssl-0.9"])).failed)



class Approvals(unittest.TestCase):
    def test_one_approval_per_host(self):
        a = npb.approval_file({"stateDir": "/s"}, "nixos-btw")
        self.assertEqual(str(a), "/s/approved/nixos-btw.json")

    def test_missing_approval_blocks(self):
        rep = npb.Report()
        approved = npb.read_approval({"stateDir": "/nonexistent-npb"}, "h", rep)
        self.assertIsNone(approved)
        self.assertTrue(rep.failed)


if __name__ == "__main__":
    unittest.main(argv=sys.argv[:1] + [a for a in sys.argv[1:] if a.startswith("-")])
