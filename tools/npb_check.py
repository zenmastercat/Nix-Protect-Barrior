"""npb-check: the build gate of Nix-Protect-Barrior.

Checks a NixOS flake *before* it is built, against the policy of the system
that is running now (/etc/nix-protect-barrior/policy.json) and against what
the owner approved before (state dir, root-owned).

  npb-check gate    --flake DIR [--host NAME] [--fast] [--json]
  npb-check approve --flake DIR [--host NAME]

Exit codes: 0 pass (warnings allowed), 1 blocked, 2 could not check.

What blocks a build (FAIL):
  * flake.lock input that is not pinned (no narHash / rev) or uses an
    unencrypted transport (http://, git://);
  * a flake input whose source (owner/repo or URL) was never approved;
  * a binary cache or signing key that neither the running policy nor an
    approval allows, a non-root trusted user, the sandbox or signature
    checks turned off, or accept-flake-config turned on;
  * a newly permitted insecure package;
  * turning Nix-Protect-Barrior off;
  * a derivation in the system closure that asks to leave the build
    sandbox (__noChroot) or to be impure (__impure).
"""
import argparse
import json
import os
import pathlib
import re
import socket
import subprocess
import sys

POLICY = pathlib.Path(os.environ.get("NPB_POLICY", "/etc/nix-protect-barrior/policy.json"))

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"


class Report:
    def __init__(self):
        self.items = []

    def add(self, level, check, msg):
        self.items.append({"level": level, "check": check, "message": msg})

    @property
    def failed(self):
        return any(i["level"] == FAIL for i in self.items)


# ------------------------------------------------------------------ helpers
def load_json(path, default):
    try:
        return json.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError):
        return default


def state_dir(policy):
    return pathlib.Path(os.environ.get("NPB_STATE_DIR", policy.get("stateDir", "/var/lib/nix-protect-barrior")))


def approval_file(policy, flake_dir, host):
    key = re.sub(r"[^A-Za-z0-9._-]", "_", f"{flake_dir}#{host}")
    return state_dir(policy) / "approved" / f"{key}.json"


def nix(*args, capture=True):
    p = subprocess.run(["nix", "--extra-experimental-features", "nix-command flakes", *args],
                       capture_output=capture, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"nix {' '.join(args[:2])} failed: {p.stderr.strip()[-800:]}")
    return p.stdout


def norm_url(u):
    return u.rstrip("/").lower()


# ------------------------------------------------------------------ flake.lock
def input_identity(locked):
    """A stable name for *where* an input comes from (not which revision)."""
    t = locked.get("type", "?")
    if t in ("github", "gitlab", "sourcehut"):
        host = locked.get("host", "")
        return f"{t}:{host + '/' if host else ''}{locked.get('owner', '')}/{locked.get('repo', '')}".lower()
    if t in ("git", "tarball", "file", "hg"):
        url = re.sub(r"[?#].*$", "", locked.get("url", ""))
        return f"{t}:{url}".lower()
    if t == "path":
        return f"path:{locked.get('path', '')}"
    return f"{t}:{json.dumps(locked, sort_keys=True)}"


def lock_inputs(lock):
    nodes = lock.get("nodes", {})
    root = lock.get("root", "root")
    out = {}
    for name, node in nodes.items():
        if name == root or "locked" not in node:
            continue
        out[name] = node
    return out


def check_lock(lock, approved_ids, rep):
    found = {}
    for name, node in sorted(lock_inputs(lock).items()):
        locked = node["locked"]
        ident = input_identity(locked)
        found[name] = ident
        t = locked.get("type")
        if not locked.get("narHash"):
            rep.add(FAIL, "lock", f"input '{name}' ({ident}) is not pinned: no narHash in flake.lock")
        if t in ("github", "gitlab", "sourcehut", "git") and not locked.get("rev"):
            rep.add(FAIL, "lock", f"input '{name}' ({ident}) has no pinned revision")
        url = locked.get("url", "")
        if url.startswith(("http://", "git://")):
            rep.add(FAIL, "lock", f"input '{name}' uses an unencrypted transport: {url}")
        if t == "path" and not locked.get("path", "").startswith("/nix/store/"):
            rep.add(WARN, "lock", f"input '{name}' is a local folder ({locked.get('path')}); "
                                  "it can change without a new lock entry")
        if approved_ids is not None and ident not in approved_ids:
            rep.add(FAIL, "lock", f"input '{name}' comes from a source never approved: {ident}")
    if approved_ids is not None:
        rep.add(PASS, "lock", f"{len(found)} flake inputs checked against {len(approved_ids)} approved sources")
    return found


# ------------------------------------------------------------------ evaluated config
SETTINGS_EXPR = """c: {
  settings = {
    substituters = c.nix.settings.substituters or [];
    trusted-public-keys = c.nix.settings.trusted-public-keys or [];
    trusted-users = c.nix.settings.trusted-users or [];
    sandbox = c.nix.settings.sandbox or true;
    require-sigs = c.nix.settings.require-sigs or true;
    accept-flake-config = c.nix.settings.accept-flake-config or false;
  };
  insecure = c.nixpkgs.config.permittedInsecurePackages or [];
  barrier = c.security.nixProtectBarrior.enable or false;
  policy = {
    allowedSubstituters = c.security.nixProtectBarrior.build.allowedSubstituters or [];
    trustedPublicKeys = c.security.nixProtectBarrior.build.allowedPublicKeys or [];
    trustedUsers = c.security.nixProtectBarrior.build.trustedUsers or [ "root" ];
    permittedInsecure = c.nixpkgs.config.permittedInsecurePackages or [];
    enabled = false;
  };
}"""


def eval_config(flake, host):
    out = nix("eval", "--json", f"{flake}#nixosConfigurations.{host}.config", "--apply", SETTINGS_EXPR)
    return json.loads(out)


def check_config(cfg, policy, approved, rep):
    s = cfg["settings"]
    allowed_subs = {norm_url(u) for u in policy.get("allowedSubstituters", [])} | \
                   {norm_url(u) for u in approved.get("substituters", [])}
    allowed_keys = set(policy.get("trustedPublicKeys", [])) | set(approved.get("trustedPublicKeys", []))
    for u in s["substituters"]:
        if norm_url(u) not in allowed_subs:
            rep.add(FAIL, "nix", f"binary cache not allowed by the running policy: {u}")
    for k in s["trusted-public-keys"]:
        if k not in allowed_keys:
            rep.add(FAIL, "nix", f"cache signing key not allowed by the running policy: {k.split(':')[0]}")
    allowed_trusted = set(policy.get("trustedUsers", ["root"])) | set(approved.get("trustedUsers", []))
    extra = [u for u in s["trusted-users"] if u not in allowed_trusted]
    if extra:
        rep.add(FAIL, "nix", f"trusted-users gives root-equivalent Nix access to: {', '.join(extra)}")
    if s["sandbox"] is not True:
        rep.add(FAIL, "nix", f"build sandbox is not strict (sandbox = {s['sandbox']})")
    if s["require-sigs"] is not True:
        rep.add(FAIL, "nix", "require-sigs is off: unsigned cache downloads would be accepted")
    if s["accept-flake-config"]:
        rep.add(FAIL, "nix", "accept-flake-config is on: any flake could add caches and settings")
    if not cfg["barrier"] and policy.get("enabled", False) and not approved.get("barrierOff", False):
        rep.add(FAIL, "barrier", "this configuration turns Nix-Protect-Barrior off")
    old = set(approved.get("insecure", [])) | set(policy.get("permittedInsecure", []))
    for p in cfg["insecure"]:
        if p in old:
            rep.add(WARN, "insecure", f"insecure package still permitted: {p}")
        else:
            rep.add(FAIL, "insecure", f"newly permitted insecure package: {p}")
    if not any(i["level"] == FAIL and i["check"] in ("nix", "barrier", "insecure") for i in rep.items):
        rep.add(PASS, "nix", "caches, keys, trusted users, sandbox and signatures match the policy")


# ------------------------------------------------------------------ closure scan
def scan_closure(flake, host, rep):
    drv = nix("eval", "--raw", f"{flake}#nixosConfigurations.{host}.config.system.build.toplevel.drvPath").strip()
    data = json.loads(nix("derivation", "show", "-r", drv))
    drvs = data.get("derivations", data)
    bad, weak = [], []
    for path, d in drvs.items():
        attrs = dict(d.get("env", {}))
        sa = d.get("structuredAttrs")
        if isinstance(sa, dict):
            attrs.update(sa)
        if str(attrs.get("__noChroot", "")).lower() in ("1", "true"):
            bad.append(f"{d.get('name', path)} asks to build outside the sandbox (__noChroot)")
        if str(attrs.get("__impure", "")).lower() in ("1", "true"):
            bad.append(f"{d.get('name', path)} is an impure derivation (__impure)")
        for o in d.get("outputs", {}).values():
            algo = (o.get("hashAlgo") or "").replace("r:", "").lower()
            if algo in ("md5", "sha1"):
                weak.append(d.get("name", path))
    for b in bad:
        rep.add(FAIL, "closure", b)
    if weak:
        rep.add(WARN, "closure", f"{len(weak)} downloads are pinned with a weak hash (md5/sha1): "
                                 f"{', '.join(sorted(set(weak))[:8])}")
    rep.add(PASS if not bad else FAIL, "closure", f"{len(drvs)} derivations scanned for sandbox escapes")


# ------------------------------------------------------------------ commands
def resolve(args):
    flake_dir = pathlib.Path(args.flake).resolve()
    if not (flake_dir / "flake.nix").exists():
        raise SystemExit(f"npb-check: {flake_dir} has no flake.nix")
    host = args.host or socket.gethostname()
    return flake_dir, host


def cmd_gate(args):
    policy = load_json(POLICY, None)
    flake_dir, host = resolve(args)
    rep = Report()
    ref = f"path:{flake_dir}" if args.path_ref else str(flake_dir)
    try:
        cfg = eval_config(ref, host)
    except RuntimeError as e:
        rep.add(FAIL, "eval", str(e))
        output(rep, args.json)
        return 2
    if policy is None:
        policy = cfg["policy"]
        rep.add(WARN, "policy", "Nix-Protect-Barrior is not installed yet: checking against the policy "
                                "of the configuration being built (first install)")
    afile = approval_file(policy, flake_dir, host)
    approved = load_json(afile, None)
    first = approved is None
    lock = load_json(flake_dir / "flake.lock", None)
    if lock is None:
        rep.add(FAIL, "lock", "flake.lock is missing or unreadable: inputs are not pinned")
        found = {}
    else:
        found = check_lock(lock, None if first else set(approved.get("inputs", {}).values()), rep)
    approved = approved or {}
    check_config(cfg, policy, approved, rep)
    if not args.fast:
        try:
            scan_closure(ref, host, rep)
        except RuntimeError as e:
            rep.add(FAIL, "closure", str(e))
    if first and lock is not None and not rep.failed:
        if os.geteuid() == 0:
            save_approval(afile, found, cfg)
            rep.add(WARN, "lock", f"first run for {flake_dir}#{host}: approved its {len(found)} current "
                                  f"inputs as the baseline ({afile})")
        else:
            rep.add(WARN, "lock", "no approved baseline yet; run 'npb-check approve' as root")
    output(rep, args.json)
    return 1 if rep.failed else 0


def save_approval(afile, inputs, cfg):
    afile.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = {"inputs": inputs}
    if cfg:
        s = cfg["settings"]
        data.update({
            "substituters": s["substituters"],
            "trustedPublicKeys": s["trusted-public-keys"],
            "trustedUsers": [u for u in s["trusted-users"]],
            "insecure": cfg["insecure"],
            "barrierOff": not cfg["barrier"],
        })
    tmp = afile.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(afile)


def cmd_approve(args):
    if os.geteuid() != 0:
        raise SystemExit("npb-check approve must run as root (doas npb-check approve ...)")
    policy = load_json(POLICY, {})
    flake_dir, host = resolve(args)
    lock = load_json(flake_dir / "flake.lock", {})
    rep = Report()
    found = check_lock(lock, None, rep)
    cfg = eval_config(str(flake_dir), host)
    print("Approving for", f"{flake_dir}#{host}:")
    for name, ident in sorted(found.items()):
        print(f"  input {name:24} {ident}")
    s = cfg["settings"]
    print("  caches:        ", ", ".join(s["substituters"]))
    print("  trusted users: ", ", ".join(s["trusted-users"]))
    print("  insecure pkgs: ", ", ".join(cfg["insecure"]) or "-")
    if not cfg["barrier"]:
        print("  NOTE: this configuration turns Nix-Protect-Barrior off")
    save_approval(approval_file(policy, flake_dir, host), found, cfg)
    print("Saved. Problems that are never approvable (unpinned inputs, http://, sandbox off,"
          " require-sigs off, __noChroot) still block the build.")
    return 0


def output(rep, as_json):
    if as_json:
        print(json.dumps({"failed": rep.failed, "items": rep.items}, indent=2))
        return
    for i in rep.items:
        print(f"{i['level']:4}  [{i['check']}] {i['message']}")
    print("npb-check:", "BLOCKED - fix the FAIL lines, or approve deliberate changes with "
          "'doas npb-check approve --flake ...'" if rep.failed else "passed")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="npb-check", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("gate", "approve"):
        p = sub.add_parser(name)
        p.add_argument("--flake", default="/etc/nixos")
        p.add_argument("--host")
        p.add_argument("--path-ref", action="store_true",
                       help="evaluate the folder as path: (includes files git does not track)")
        if name == "gate":
            p.add_argument("--fast", action="store_true", help="skip the closure scan")
            p.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        return cmd_gate(args) if args.cmd == "gate" else cmd_approve(args)
    except RuntimeError as e:
        print(f"npb-check: could not check: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
