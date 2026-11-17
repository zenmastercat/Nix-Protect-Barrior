# Install and daily use

This guide adds Nix-Protect-Barrior to a NixOS flake configuration in `/etc/nixos` and covers the first run, the short commands and what to do when the gate blocks.

## 1. Add the input and the module

In `flake.nix`:

```nix
inputs.nix-protect-barrior = {
  url = "github:zenmastercat/Nix-Protect-Barrior";
  inputs.nixpkgs.follows = "nixpkgs";
};
```

In a NixOS module of your host (pass `inputs` through `specialArgs` or your flake framework):

```nix
{ inputs, pkgs, ... }:
{
  imports = [ inputs.nix-protect-barrior.nixosModules.default ];

  # A Nix without the 2026-10-13 daemon CVEs (>= 2.34.9 or >= 2.35.3).
  # The module refuses older versions.
  nix.package = pkgs.nixVersions.nix_2_34;

  security.nixProtectBarrior = {
    enable = true;

    # Every binary cache and signing key the system uses must be listed.
    # Check each key against real signatures before you add it:
    #   nix store verify --no-contents --sigs-needed 1 \
    #     --option trusted-public-keys "<key>" <a store path from that cache>
    build.allowedSubstituters = [ "https://cache.nixos.org" ];
    build.allowedPublicKeys = [ "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=" ];

    # Network: pick what fits your machine.
    network.closeSsh = true;                 # SSH only from this PC
    network.localOnly.tcp = [ 11434 ];       # e.g. a local LLM API
    network.dockerLocalOnly = true;          # Docker publishes on 127.0.0.1
    network.ollamaLocalOrigins = true;       # web pages cannot call Ollama
  };
}
```

If the build stops with a `Nix-Protect-Barrior:` assertion, the message names the cache, key, trusted user or `extraOptions` line to fix.

If `/etc/nixos` is a git repository, `git add` the new module file: flakes only see tracked files.

## 2. First install

The barrier is not installed yet, so use plain `nixos-rebuild` once:

```sh
doas nixos-rebuild boot --flake /etc/nixos#<host>
df -h /boot          # check that the boot partition has room
```

Reboot.

## 3. Approve once

```sh
barrier-approve
```

This lists every flake input source, every binary cache and trusted user, and every place where trust grows. Type `APPROVE` (or `WIDEN` when it asks) to save. Until you approve, every gated rebuild, including the automatic upgrade, is blocked. Blocking is safe: nothing changes.

## 4. Daily use

| Short command | Runs | When |
|---|---|---|
| `rebuild` | `doas npb-rebuild switch` | instead of `nixos-rebuild switch` |
| `rebuild-boot` | `doas npb-rebuild boot` | change becomes active after the next boot |
| `barrier-approve` | `doas npb-check approve --flake /etc/nixos` | after a deliberate change: new input, cache, key, insecure package, or a protection turned off |
| `barrier-status` | `doas npb-status` | latest audit and store check |
| `barrier-audit` | starts the audit, then shows the status | after installing software or changing start-up files |
| `barrier-verify` | starts the store check (with repair), then shows the status | when you suspect damaged or changed store files |

The short commands use `doas` when it is enabled, otherwise `sudo`. Turn them off with `security.nixProtectBarrior.gate.aliases = false`.

`npb-rebuild` takes every `nixos-rebuild` argument. `--flake` defaults to `/etc/nixos#<hostname>`.

## 5. When the gate blocks

The gate prints one line per check. `FAIL` lines say what blocks:

| FAIL message | Meaning | What to do |
|---|---|---|
| `no approved baseline for host ...` | first run, or the approval file was removed | `barrier-approve` |
| `input '...' comes from a source never approved` | a new flake input, or an input now points to another owner/repo | check that you added it; then `barrier-approve` |
| `binary cache not allowed` / `cache signing key not allowed` | a cache or key outside `build.allowed*` | add it to the allowlist after checking it, rebuild, approve |
| `trusted-users gives root-equivalent Nix access` | a user other than root would be trusted by the daemon | remove it; trusted users can get root |
| `this configuration turns off ...` / `removes the local-only ...` | a protection is weaker than on the running system | undo it, or `barrier-approve` if you mean it |
| `newly permitted insecure package` | `nixpkgs.config.permittedInsecurePackages` grew | check why the package is needed; then approve |
| `not pinned` / `unencrypted transport` / `sandbox` / `require-sigs` / `__noChroot` | never approvable | fix the input or setting |
| `approvals are root-only` | the gate ran without root | run it through `rebuild` or `doas` |

## 6. The automatic upgrade

With `system.autoUpgrade` enabled (and `allowReboot` off), the barrier replaces its script:

1. copy the flake from `system.autoUpgrade.flake` into the store;
2. update the inputs named with `--update-input` in a temporary copy;
3. freeze that copy, run the full gate on it, closure scan included;
4. build exactly that frozen copy with `nixos-rebuild <operation>`.

If the gate blocks, nothing changes. Check `systemctl status nixos-upgrade` and `journalctl -u nixos-upgrade`.

`--update-input X` does nothing when `X` is a `follows` of another input. In that case Nix prints `'X' does not match any input of this flake`.

## 7. Services

| Service | When | Output |
|---|---|---|
| `nix-protect-barrior-audit` | daily 05:30 and 15 min after boot | `/var/lib/nix-protect-barrior/audit-latest.json`, journal |
| `nix-protect-barrior-verify` | weekly, Sunday 03:30, at idle priority | `/var/lib/nix-protect-barrior/verify-latest.json`, journal |

The first audit records a baseline of setuid files, unmanaged `/etc` files and start-up files. Later runs report what is new or changed. After you check a new start-up file and it is yours, run `doas npb-audit --accept`.

Show only problems: `journalctl -u nix-protect-barrior-audit -p warning`.

## 8. Undo

Set `security.nixProtectBarrior.enable = false;` and approve once with `barrier-approve`: turning the barrier off is a protection change and is blocked otherwise. Then rebuild.
