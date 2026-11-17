"""npb-status: show the latest Nix-Protect-Barrior audit and store check."""
import json
import re
import os
import pathlib
import sys

ROOT = os.geteuid() == 0
POLICY = pathlib.Path("/etc/nix-protect-barrior/policy.json" if ROOT else
                      os.environ.get("NPB_POLICY", "/etc/nix-protect-barrior/policy.json"))


def load(path):
    try:
        return json.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError):
        return None


def main():
    policy = load(POLICY) or {}
    state = pathlib.Path(policy.get("stateDir", "/var/lib/nix-protect-barrior") if ROOT else
                         os.environ.get("NPB_STATE_DIR", policy.get("stateDir", "/var/lib/nix-protect-barrior")))
    if not os.access(state, os.R_OK | os.X_OK):
        print(f"npb-status: {state} is root-only; run: doas npb-status")
        return 2
    audit = load(state / "audit-latest.json")
    verify = load(state / "verify-latest.json")
    print("Nix-Protect-Barrior")
    if audit:
        c = audit["counts"]
        print(f"  audit   {audit['time']}: {c['high']} high, {c['medium']} medium, {c['low']} low")
        for f in audit["findings"]:
            if f["severity"] in ("high", "medium"):
                msg = re.sub(r"[\x00-\x1f\x7f]", "?", f["message"])
                print(f"    {f['severity'].upper():6} [{f['check']}] {msg}")
    else:
        print("  audit   no report yet (systemctl start nix-protect-barrior-audit)")
    if verify:
        state_txt = "OK" if verify["ok"] else "PROBLEM"
        print(f"  store   {verify['time']}: {state_txt}, {len(verify['modified'])} modified, "
              f"{len(verify['repaired'])} repaired ({verify['seconds']} s)")
        for p in verify["unrepaired"]:
            print(f"    MODIFIED {p}")
    else:
        print("  store   no check yet (systemctl start nix-protect-barrior-verify)")
    return 1 if (audit and audit["counts"]["high"]) or (verify and not verify["ok"]) else 0


if __name__ == "__main__":
    sys.exit(main())
