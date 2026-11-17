"""npb-audit: daily runtime audit of Nix-Protect-Barrior (runs as root).

  npb-audit            run all checks, write the report, print findings
  npb-audit --accept   re-baseline the watched files (after you checked them)

Report: <stateDir>/audit-latest.json (+ dated copies). Findings go to the
journal with priorities, so `journalctl -p warning -u nix-protect-barrior-audit`
shows only problems.

Checks:
  nix       daemon settings (trusted users, sandbox, signatures, caches, keys),
            accepted per-user flake settings
  network   listeners reachable from the network, ports Docker publishes past
            the firewall, SSH password login reachable from the network
  system    extra UID-0 accounts, /etc/ld.so.preload, new setuid/setgid files,
            new unmanaged files in /etc
  persist   new or changed autostart / shell-start / systemd-user / SSH-key
            files in watched home folders and cron spools
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

POLICY = pathlib.Path(os.environ.get("NPB_POLICY", "/etc/nix-protect-barrior/policy.json"))
SEV_PRIO = {"high": 3, "medium": 4, "low": 5, "info": 6}

HOME_WATCH = [
    ".config/autostart", ".config/systemd/user", ".config/environment.d",
    ".profile", ".bash_profile", ".bash_login", ".bashrc", ".zshrc", ".zprofile",
    ".config/fish/config.fish", ".config/fish/conf.d", ".xprofile", ".xinitrc",
    ".ssh/authorized_keys", ".ssh/authorized_keys2", ".ssh/rc", ".pam_environment",
    ".local/share/nix/trusted-settings.json", ".config/nix/nix.conf",
]
SYSTEM_WATCH = ["/var/spool/cron", "/etc/cron.d", "/root/.ssh/authorized_keys", "/root/.profile",
                "/root/.bashrc", "/root/.config/nix/nix.conf"]
ETC_MUTABLE = {
    "passwd", "shadow", "group", "gshadow", "subuid", "subgid", "machine-id", "adjtime", "resolv.conf",
    "NIXOS", ".clean", ".updated", "mtab", "localtime", "hostname", "ld.so.cache", ".pwd.lock",
    "group-", "passwd-", "shadow-", "gshadow-", "subuid-", "subgid-", "printcap", "fstab", "sudoers",
    "doas.conf", "hosts", "nsswitch.conf", "os-release", "zfs", "nixos", "static",
}


class Audit:
    def __init__(self):
        self.findings = []

    def add(self, sev, check, msg):
        self.findings.append({"severity": sev, "check": check, "message": msg})


def load_json(path, default):
    try:
        return json.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError):
        return default


def sh(*cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else ""


# ------------------------------------------------------------------ nix
def nix_config():
    out = sh("nix", "--extra-experimental-features", "nix-command", "config", "show")
    cfg = {}
    for line in out.splitlines():
        if " = " in line:
            k, v = line.split(" = ", 1)
            cfg[k.strip()] = v.strip()
    return cfg


def check_nix(a, policy):
    cfg = nix_config()
    if not cfg:
        a.add("medium", "nix", "could not read the Nix daemon settings")
        return
    allowed_users = set(policy.get("trustedUsers", ["root"]))
    extra = [u for u in cfg.get("trusted-users", "").split() if u not in allowed_users]
    if extra:
        a.add("high", "nix", f"trusted-users gives root-equivalent Nix access to: {', '.join(sorted(set(extra)))}")
    if cfg.get("sandbox") != "true":
        a.add("high", "nix", f"build sandbox is not strict (sandbox = {cfg.get('sandbox')})")
    if cfg.get("require-sigs") != "true":
        a.add("high", "nix", "require-sigs is off")
    if cfg.get("accept-flake-config") == "true":
        a.add("high", "nix", "accept-flake-config is on")
    subs = {s.rstrip("/").lower() for s in policy.get("allowedSubstituters", [])}
    for s in cfg.get("substituters", "").split() + cfg.get("trusted-substituters", "").split():
        if s.rstrip("/").lower() not in subs:
            a.add("high", "nix", f"binary cache outside the policy: {s}")
    keys = set(policy.get("trustedPublicKeys", []))
    for k in cfg.get("trusted-public-keys", "").split():
        if k not in keys:
            a.add("high", "nix", f"trusted signing key outside the policy: {k}")
    for u in policy.get("watchUsers", []):
        ts = pathlib.Path(u["home"]) / ".local/share/nix/trusted-settings.json"
        data = load_json(ts, {})
        accepted = [f"{k}={v2}" for k, v in data.items() if isinstance(v, dict) for v2, ok in v.items() if ok]
        if accepted:
            a.add("low", "nix", f"{u['name']} accepted flake settings ({ts}): {'; '.join(accepted)[:300]} "
                                "- ignored while the user is not trusted")


# ------------------------------------------------------------------ network
def listeners():
    out = sh("ss", "-H", "-tuln")
    res = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, local = parts[0], parts[4]
        m = re.match(r"^(.*):(\d+)$", local)
        if not m:
            continue
        addr, port = m.group(1).strip("[]"), int(m.group(2))
        addr = addr.split("%")[0]
        res.append((proto, addr, port))
    return res


def is_loopback(addr):
    return addr in ("127.0.0.1", "::1", "localhost") or addr.startswith("127.")


def in_ranges(port, ports, ranges):
    return port in ports or any(r["from"] <= port <= r["to"] for r in ranges)


def check_network(a, policy):
    fw = policy.get("firewall", {})
    lo = policy.get("localOnly", {})
    seen = set()
    for proto, addr, port in listeners():
        if is_loopback(addr) or (proto, port) in seen:
            continue
        seen.add((proto, port))
        kind = "tcp" if proto.startswith("tcp") else "udp"
        if not fw.get("enable", True):
            a.add("high", "network", f"{kind}/{port} listens on {addr or '*'} and the firewall is off")
            continue
        opened = in_ranges(port, fw.get(f"allowed{kind.upper()}Ports", []),
                           fw.get(f"allowed{kind.upper()}PortRanges", []))
        local_only = in_ranges(port, lo.get(kind, []), lo.get(f"{kind}Ranges", []))
        if opened and not local_only:
            a.add("info", "network", f"{kind}/{port} is reachable from the network (opened in the firewall)")
    nat = sh("iptables", "-t", "nat", "-S", "DOCKER")
    for line in nat.splitlines():
        if "DNAT" not in line:
            continue
        m = re.search(r"-d (\S+)", line)
        dport = re.search(r"--dport (\d+)", line)
        if dport and not (m and m.group(1).startswith("127.")):
            a.add("medium", "network", f"Docker publishes port {dport.group(1)} to the network "
                                       "(Docker bypasses the NixOS firewall)")
    ssh = policy.get("ssh", {})
    if ssh.get("enable") and ssh.get("passwordAuth") and not ssh.get("closed"):
        a.add("high", "network", "SSH accepts password logins from the network")


# ------------------------------------------------------------------ system
def check_system(a, state, baseline, new_base):
    for line in pathlib.Path("/etc/passwd").read_text().splitlines():
        f = line.split(":")
        if len(f) > 3 and f[2] == "0" and f[0] != "root":
            a.add("high", "system", f"extra account with UID 0: {f[0]}")
    if pathlib.Path("/etc/ld.so.preload").exists():
        a.add("high", "system", "/etc/ld.so.preload exists (forces a library into every program)")

    found = set()
    for top in ("/", "/home", "/var", "/root", "/opt", "/usr", "/srv"):
        if not os.path.isdir(top):
            continue
        out = subprocess.run(["find", top, "-xdev", "(", "-path", "/nix", "-o", "-path", "/proc", "-o",
                              "-path", "/run", "-o", "-path", "/sys", ")", "-prune", "-o", "-type", "f",
                              "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-print"],
                             capture_output=True, text=True).stdout
        found |= {p for p in out.splitlines() if p}
    new_base["setuid"] = sorted(found)
    if "setuid" in baseline:
        for p in sorted(found - set(baseline["setuid"])):
            a.add("high", "system", f"new setuid/setgid file outside the Nix store: {p}")
    elif found:
        a.add("medium", "system", f"setuid/setgid files outside the Nix store: {', '.join(sorted(found))[:300]}")

    etc = set()
    for p in pathlib.Path("/etc").iterdir():
        if p.name in ETC_MUTABLE:
            continue
        try:
            target = os.readlink(p) if p.is_symlink() else ""
        except OSError:
            target = ""
        if target.startswith(("/etc/static", "/nix/store")):
            continue
        etc.add(p.name)
    new_base["etc"] = sorted(etc)
    if "etc" in baseline:
        for n in sorted(etc - set(baseline["etc"])):
            a.add("medium", "system", f"new file in /etc that NixOS does not manage: /etc/{n}")


def file_hashes(paths):
    res = {}
    for base in paths:
        b = pathlib.Path(base)
        files = [b] if b.is_file() else (sorted(x for x in b.rglob("*") if x.is_file()) if b.is_dir() else [])
        for f in files:
            try:
                res[str(f)] = hashlib.sha256(f.read_bytes()).hexdigest()
            except OSError:
                pass
    return res


def check_persistence(a, policy, baseline, new_base):
    paths = list(SYSTEM_WATCH)
    for u in policy.get("watchUsers", []):
        paths += [str(pathlib.Path(u["home"]) / p) for p in HOME_WATCH]
    now = file_hashes(paths)
    new_base["persist"] = now
    old = baseline.get("persist")
    if old is None:
        a.add("info", "persist", f"baseline created for {len(now)} start-up and key files")
        return
    for f in sorted(set(now) - set(old)):
        a.add("medium", "persist", f"new start-up/key file: {f} (check it; 'npb-audit --accept' if it is yours)")
    for f in sorted(f for f in now if f in old and now[f] != old[f]):
        a.add("low", "persist", f"changed start-up/key file: {f}")
    for f in sorted(set(old) - set(now)):
        a.add("info", "persist", f"removed start-up/key file: {f}")


# ------------------------------------------------------------------ main
def main(argv=None):
    ap = argparse.ArgumentParser(prog="npb-audit", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--accept", action="store_true", help="re-baseline watched files and setuid list")
    args = ap.parse_args(argv)
    policy = load_json(POLICY, {})
    state = pathlib.Path(os.environ.get("NPB_STATE_DIR", policy.get("stateDir", "/var/lib/nix-protect-barrior")))
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    base_file = state / "audit-baseline.json"
    baseline = {} if args.accept else load_json(base_file, {})
    new_base = {}
    a = Audit()
    for name, fn in (("nix", lambda: check_nix(a, policy)),
                     ("network", lambda: check_network(a, policy)),
                     ("system", lambda: check_system(a, state, baseline, new_base)),
                     ("persist", lambda: check_persistence(a, policy, baseline, new_base))):
        try:
            fn()
        except Exception as e:  # one broken check must not hide the others
            a.add("medium", name, f"check failed: {e}")
    # Baselines only grow by explicit acceptance; first run creates them.
    merged = dict(baseline)
    for k, v in new_base.items():
        if args.accept or k not in baseline:
            merged[k] = v
    base_file.write_text(json.dumps(merged, indent=1, sort_keys=True))
    os.chmod(base_file, 0o600)

    counts = {s: sum(1 for f in a.findings if f["severity"] == s) for s in SEV_PRIO}
    report = {"time": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
              "counts": counts, "findings": a.findings}
    (state / "audit-latest.json").write_text(json.dumps(report, indent=2))
    hist = state / "history"
    hist.mkdir(exist_ok=True)
    (hist / f"audit-{dt.date.today().isoformat()}.json").write_text(json.dumps(report, indent=2))
    for f in sorted(a.findings, key=lambda f: SEV_PRIO[f["severity"]]):
        print(f"<{SEV_PRIO[f['severity']]}>{f['severity'].upper():6} [{f['check']}] {f['message']}")
    print(f"<6>npb-audit: {counts['high']} high, {counts['medium']} medium, {counts['low']} low, "
          f"{counts['info']} info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
