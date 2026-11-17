"""npb-check: the build gate of Nix-Protect-Barrior.

Checks a NixOS flake *before* it is built, against the policy of the system
that is running now (/etc/nix-protect-barrior/policy.json) and against what
the owner approved before (root-only state dir, one approval per host).

  npb-check gate    --flake DIR [--host NAME] [--fast] [--json]
  npb-check approve --flake DIR [--host NAME]      (root, asks you to confirm)
  npb-check archive --flake REF                    (prints a frozen store copy)

Exit codes: 0 pass (warnings allowed), 1 blocked, 2 could not check.

What blocks a build (FAIL):
  * flake.lock input that is not pinned (no narHash / rev) or uses an
    unencrypted transport (http://, git://);
  * a flake input whose source (owner/repo or URL) was never approved;
  * a binary cache, signing key or trusted user that neither the running
    policy nor an approval allows - also through extra-* settings and
    nix.extraOptions; the sandbox or signature checks off; accept-flake-config on;
  * a newly permitted insecure package;
  * turning Nix-Protect-Barrior or any of its protections off, or removing a
    local-only port, unless approved;
  * a derivation in the system closure that asks to leave the build sandbox
    (__noChroot) or to be impure (__impure);
  * no approved baseline yet, or approvals that cannot be read (not root).
"""
import argparse
import json
import os
import pathlib
import re
import socket
import subprocess
import sys

ROOT = os.geteuid() == 0
# Root ignores environment overrides, so a caller cannot point it at another policy.
POLICY = pathlib.Path("/etc/nix-protect-barrior/policy.json" if ROOT else
                      os.environ.get("NPB_POLICY", "/etc/nix-protect-barrior/policy.json"))

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
LIST_KEYS = {
    "substituters": "substituters", "extra-substituters": "substituters",
    "trusted-substituters": "substituters", "extra-trusted-substituters": "substituters",
    "trusted-public-keys": "trusted-public-keys", "extra-trusted-public-keys": "trusted-public-keys",
    "trusted-users": "trusted-users", "extra-trusted-users": "trusted-users",
}
BOOL_KEYS = ("sandbox", "require-sigs", "accept-flake-config")
HARDENING_BOOLS = {
    "barrier": "Nix-Protect-Barrior", "buildEnable": "Nix daemon hardening",
    "gateEnable": "the build gate", "gateAutoUpgrade": "the gate before auto-upgrade",
    "sysctls": "kernel hardening settings", "restrictPtrace": "ptrace restriction",
    "closeSsh": "SSH closed to the network", "dockerLocalOnly": "Docker publishing on 127.0.0.1",
    "ollamaLocalOrigins": "Ollama origin limit", "verify": "store verify service",
    "autoRepair": "store auto-repair", "audit": "daily audit",
}
HARDENING_LISTS = {"localTcp": "local-only TCP port", "localUdp": "local-only UDP port",
                   "localTcpRanges": "local-only TCP range", "localUdpRanges": "local-only UDP range"}


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
    if ROOT:
        return pathlib.Path(policy.get("stateDir", "/var/lib/nix-protect-barrior"))
    return pathlib.Path(os.environ.get("NPB_STATE_DIR", policy.get("stateDir", "/var/lib/nix-protect-barrior")))


def approval_file(policy, host):
    """One approval per host: the same baseline for /etc/nixos, a store copy or auto-upgrade."""
    return state_dir(policy) / "approved" / f"{re.sub(r'[^A-Za-z0-9._-]', '_', host)}.json"


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
    return {n: v for n, v in nodes.items() if n != root and "locked" in v}


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
SETTINGS_EXPR = """c:
let
  s = c.nix.settings;
  b = c.security.nixProtectBarrior or {};
  get = path: def: c.lib.attrByPath path def b;
  ranges = rs: map (r: "${toString r.from}-${toString r.to}") rs;
in {
  settings = {
    substituters = (s.substituters or []) ++ (s.extra-substituters or [])
      ++ (s.trusted-substituters or []) ++ (s.extra-trusted-substituters or []);
    trusted-public-keys = (s.trusted-public-keys or []) ++ (s.extra-trusted-public-keys or []);
    trusted-users = (s.trusted-users or []) ++ (s.extra-trusted-users or []);
    sandbox = s.sandbox or true;
    require-sigs = s.require-sigs or true;
    accept-flake-config = s.accept-flake-config or false;
  };
  extraOptions = c.nix.extraOptions or "";
  insecure = c.nixpkgs.config.permittedInsecurePackages or [];
  hardening = {
    barrier = get [ "enable" ] false;
    buildEnable = get [ "build" "enable" ] false;
    gateEnable = get [ "gate" "enable" ] false;
    gateAutoUpgrade = get [ "gate" "autoUpgrade" ] false;
    sysctls = get [ "runtime" "sysctls" ] false;
    restrictPtrace = get [ "runtime" "restrictPtrace" ] false;
    closeSsh = get [ "network" "closeSsh" ] false;
    dockerLocalOnly = get [ "network" "dockerLocalOnly" ] false;
    ollamaLocalOrigins = get [ "network" "ollamaLocalOrigins" ] false;
    verify = get [ "verify" "enable" ] false;
    autoRepair = get [ "verify" "autoRepair" ] false;
    audit = get [ "audit" "enable" ] false;
    localTcp = get [ "network" "localOnly" "tcp" ] [];
    localUdp = get [ "network" "localOnly" "udp" ] [];
    localTcpRanges = ranges (get [ "network" "localOnly" "tcpRanges" ] []);
    localUdpRanges = ranges (get [ "network" "localOnly" "udpRanges" ] []);
  };
  policy = {
    allowedSubstituters = get [ "build" "allowedSubstituters" ] [];
    trustedPublicKeys = get [ "build" "allowedPublicKeys" ] [];
    trustedUsers = get [ "build" "trustedUsers" ] [ "root" ];
    permittedInsecure = c.nixpkgs.config.permittedInsecurePackages or [];
  };
}"""


def eval_config(flake, host):
    out = nix("eval", "--json", f"{flake}#nixosConfigurations.{host}",
              "--apply", f"sys: let c = sys.config // {{ lib = sys.pkgs.lib; }}; in ({SETTINGS_EXPR}) c")
    return apply_extra_options(json.loads(out))


def apply_extra_options(cfg):
    """Fold nix.extraOptions (appended verbatim to nix.conf) into the checked settings."""
    s = cfg["settings"]
    cfg["includes"] = []
    for raw in cfg.get("extraOptions", "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("include ", "!include ")):
            cfg["includes"].append(line)
            continue
        if "=" not in line:
            continue
        key, val = (x.strip() for x in line.split("=", 1))
        if key in LIST_KEYS:
            s[LIST_KEYS[key]] = list(s[LIST_KEYS[key]]) + val.split()
        elif key in BOOL_KEYS:
            s[key] = {"true": True, "false": False}.get(val, val)
    return cfg


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
    extra = sorted({u for u in s["trusted-users"] if u not in allowed_trusted})
    if extra:
        rep.add(FAIL, "nix", f"trusted-users gives root-equivalent Nix access to: {', '.join(extra)}")
    if s["sandbox"] is not True:
        rep.add(FAIL, "nix", f"build sandbox is not strict (sandbox = {s['sandbox']})")
    if s["require-sigs"] is not True:
        rep.add(FAIL, "nix", "require-sigs is off: unsigned cache downloads would be accepted")
    if s["accept-flake-config"] is True or s["accept-flake-config"] == "true":
        rep.add(FAIL, "nix", "accept-flake-config is on: any flake could add caches and settings")
    for inc in cfg.get("includes", []):
        rep.add(FAIL, "nix", f"nix.extraOptions includes another file the gate cannot check: {inc}")
    old = set(approved.get("insecure", [])) | set(policy.get("permittedInsecure", []))
    for p in cfg["insecure"]:
        if p in old:
            rep.add(WARN, "insecure", f"insecure package still permitted: {p}")
        else:
            rep.add(FAIL, "insecure", f"newly permitted insecure package: {p}")
    check_hardening(cfg["hardening"], policy.get("hardening"), approved.get("hardening"), rep)
    if not any(i["level"] == FAIL and i["check"] in ("nix", "barrier", "insecure") for i in rep.items):
        rep.add(PASS, "nix", "caches, keys, trusted users, sandbox, signatures and protections match the policy")


def check_hardening(cand, running, approved, rep):
    """Fail when the candidate weakens a protection the running system has, unless approved exactly."""
    if running is None:
        return
    if approved is not None and approved == cand:
        return
    for k, label in HARDENING_BOOLS.items():
        if running.get(k) and not cand.get(k):
            rep.add(FAIL, "barrier", f"this configuration turns off {label}")
    for k, label in HARDENING_LISTS.items():
        for v in sorted(set(map(str, running.get(k, []))) - set(map(str, cand.get(k, [])))):
            rep.add(FAIL, "barrier", f"this configuration removes the {label} {v}")


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


def read_approval(policy, host, rep):
    afile = approval_file(policy, host)
    try:
        return json.loads(afile.read_text())
    except FileNotFoundError:
        if not os.access(afile.parent.parent, os.X_OK) and not ROOT:
            rep.add(FAIL, "approval", "approvals are root-only: run the gate as root (doas)")
        else:
            rep.add(FAIL, "approval", f"no approved baseline for host '{host}' yet: "
                                      f"run 'doas npb-check approve --flake <dir> --host {host}' once")
    except PermissionError:
        rep.add(FAIL, "approval", "approvals are root-only: run the gate as root (doas)")
    except ValueError:
        rep.add(FAIL, "approval", f"approval file {afile} is damaged")
    return None


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
    approved = read_approval(policy, host, rep)
    lock = load_json(flake_dir / "flake.lock", None)
    if lock is None:
        rep.add(FAIL, "lock", "flake.lock is missing or unreadable: inputs are not pinned")
    else:
        check_lock(lock, set((approved or {}).get("inputs", {}).values()) if approved else None, rep)
    check_config(cfg, policy, approved or {}, rep)
    if not args.fast:
        try:
            scan_closure(ref, host, rep)
        except RuntimeError as e:
            rep.add(FAIL, "closure", str(e))
    output(rep, args.json)
    return 1 if rep.failed else 0


def save_approval(afile, inputs, cfg):
    afile.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    s = cfg["settings"]
    data = {
        "inputs": inputs,
        "substituters": s["substituters"],
        "trustedPublicKeys": s["trusted-public-keys"],
        "trustedUsers": sorted(set(s["trusted-users"])),
        "insecure": cfg["insecure"],
        "hardening": cfg["hardening"],
    }
    tmp = afile.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
    tmp.replace(afile)


def cmd_approve(args):
    if not ROOT:
        raise SystemExit("npb-check approve must run as root (doas npb-check approve ...)")
    policy = load_json(POLICY, None)
    flake_dir, host = resolve(args)
    cfg = eval_config(str(flake_dir), host)
    if policy is None:
        policy = cfg["policy"]
    lock = load_json(flake_dir / "flake.lock", {})
    rep = Report()
    found = check_lock(lock, None, rep)
    if rep.failed:
        output(rep, False)
        raise SystemExit("npb-check: unpinned or unencrypted inputs can never be approved")
    old = load_json(approval_file(policy, host), {})
    old_ids = set(old.get("inputs", {}).values())
    s = cfg["settings"]
    widen = []
    print(f"Approve {flake_dir}#{host}:")
    for name, ident in sorted(found.items()):
        new = ident not in old_ids
        print(f"  input {name:24} {ident}{'   <- NEW' if new and old_ids else ''}")
    allowed = {norm_url(u) for u in policy.get("allowedSubstituters", [])}
    for u in s["substituters"]:
        if norm_url(u) not in allowed:
            widen.append(f"cache {u}")
    for k in s["trusted-public-keys"]:
        if k not in policy.get("trustedPublicKeys", []):
            widen.append(f"signing key {k}")
    for u in sorted(set(s["trusted-users"]) - set(policy.get("trustedUsers", ["root"]))):
        widen.append(f"TRUSTED USER {u} (root-equivalent)")
    weak = Report()
    check_hardening(cfg["hardening"], policy.get("hardening"), None, weak)
    widen += [i["message"] for i in weak.items]
    print("  insecure pkgs: ", ", ".join(cfg["insecure"]) or "-")
    for w in widen:
        print(f"  WIDENS TRUST: {w}")
    if not sys.stdin.isatty():
        raise SystemExit("npb-check approve needs a person at a terminal; nothing was saved")
    word = "WIDEN" if widen else "APPROVE"
    answer = input(f"Type {word} to save this approval: ").strip()
    if answer != word:
        print("Not approved; nothing was saved.")
        return 1
    save_approval(approval_file(policy, host), found, cfg)
    print("Saved. Unpinned inputs, http://, sandbox off, require-sigs off and __noChroot can never be approved.")
    return 0


def cmd_archive(args):
    """Copy a flake (and its inputs) into the store once, so gate and build read the same files."""
    out = nix("flake", "archive", "--json", args.flake)
    print(json.loads(out)["path"])
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
    for name in ("gate", "approve", "archive"):
        p = sub.add_parser(name)
        p.add_argument("--flake", default="/etc/nixos")
        if name == "archive":
            continue
        p.add_argument("--host")
        if name == "gate":
            p.add_argument("--path-ref", action="store_true",
                           help="evaluate the folder as path: (includes files git does not track)")
            p.add_argument("--fast", action="store_true", help="skip the closure scan")
            p.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        return {"gate": cmd_gate, "approve": cmd_approve, "archive": cmd_archive}[args.cmd](args)
    except RuntimeError as e:
        print(f"npb-check: could not check: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
