"""npb-verify: store integrity check of Nix-Protect-Barrior (runs as root).

  npb-verify [--repair] [ROOT ...]

Re-hashes every store path in the closure of the given roots (default: the
running system and the boot profile) and compares it with the hash Nix
recorded when the path was added. A path whose files were changed on disk
(tampering, disk corruption) is reported; with --repair it is replaced by a
fresh copy: downloaded from a signed binary cache, or rebuilt.

Report: <stateDir>/verify-latest.json.
"""
import argparse
import datetime as dt
import json
import os
import pathlib
import re
import subprocess
import sys

POLICY = pathlib.Path(os.environ.get("NPB_POLICY", "/etc/nix-protect-barrior/policy.json"))
DEFAULT_ROOTS = ["/run/current-system", "/nix/var/nix/profiles/system"]
MODIFIED = re.compile(r"path '(/nix/store/[^']+)' was modified")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="npb-verify", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repair", action="store_true", help="replace modified paths with a fresh copy")
    ap.add_argument("roots", nargs="*")
    args = ap.parse_args(argv)
    try:
        policy = json.loads(POLICY.read_text())
    except (OSError, ValueError):
        policy = {}
    state = pathlib.Path(os.environ.get("NPB_STATE_DIR", policy.get("stateDir", "/var/lib/nix-protect-barrior")))
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    roots = [r for r in (args.roots or DEFAULT_ROOTS) if os.path.exists(r)]

    start = dt.datetime.now().astimezone()
    p = subprocess.run(["nix", "--extra-experimental-features", "nix-command", "store", "verify",
                        "--no-trust", "--recursive", *roots], capture_output=True, text=True)
    modified = sorted(set(MODIFIED.findall(p.stderr)))
    other_errors = [l for l in p.stderr.splitlines() if l.startswith("error") and "was modified" not in l]

    repaired, unrepaired = [], []
    if modified and args.repair:
        for path in modified:
            r = subprocess.run(["nix-store", "--repair-path", path], capture_output=True, text=True)
            (repaired if r.returncode == 0 else unrepaired).append(path)
    elif modified:
        unrepaired = modified

    report = {
        "time": start.isoformat(timespec="seconds"),
        "seconds": round((dt.datetime.now().astimezone() - start).total_seconds()),
        "roots": roots,
        "modified": modified,
        "repaired": repaired,
        "unrepaired": unrepaired,
        "errors": other_errors[:20],
        "ok": not unrepaired and not other_errors,
    }
    (state / "verify-latest.json").write_text(json.dumps(report, indent=2))
    for path in repaired:
        print(f"<4>REPAIRED  {path} was modified on disk; replaced with a verified copy")
    for path in unrepaired:
        print(f"<3>MODIFIED  {path} differs from its recorded hash"
              + ("" if args.repair else " (run npb-verify --repair)"))
    for e in other_errors[:20]:
        print(f"<3>{e}")
    print(f"<6>npb-verify: {len(modified)} modified, {len(repaired)} repaired, "
          f"{len(unrepaired)} not repaired, {report['seconds']} s")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
