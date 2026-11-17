# Nix-Protect-Barrior

A security layer for a NixOS desktop. It puts a gate in front of rebuilds and the automatic upgrade, closes the usual ways into a NixOS PC, and runs services that find and repair problems.

| Layer | What it does | Stops |
|---|---|---|
| **build** | Nix daemon: only `root` is a trusted user, strict sandbox, `require-sigs`, binary caches and signing keys from an allowlist, also through `extra-*` settings; `nix.extraOptions` may not set trust; refuses a Nix with known daemon CVEs | a user-level program getting root through the daemon (trusted-users, CVE-2026-110450); poisoned or unknown caches; fake signing keys |
| **gate** | `npb-rebuild` (and the short command `rebuild`) and the automatic upgrade freeze the flake into the store, check that frozen copy, and build exactly that copy | unpinned or `http://` inputs; inputs from a source you never approved; new caches, keys or trusted users; sandbox or signatures turned off; newly permitted insecure packages; turning the barrier or any of its protections off; derivations that ask to leave the sandbox (`__noChroot`, `__impure`) |
| **network** | local-only ports (only this PC, Docker bridges and `lo`), SSH closed to the network, Docker publishing on `127.0.0.1` (default bridge and new compose networks), Ollama origins limited | LAN access to unauthenticated services (Ollama API, relays), SSH password guessing, web pages calling a local LLM API |
| **runtime** | kernel settings (`ptrace_scope=1`, `dmesg_restrict`, `kptr_restrict=2`, no unprivileged BPF, no kexec, protected links/FIFOs, no ICMP redirects, …); your own explicit values win | common steps after a break-in: reading other processes' memory, kernel address leaks, swapping the kernel |
| **verify** (weekly) | re-hashes every store path of the running system and the boot profile; repairs changed ones with a copy from a signed cache or a rebuild | tampered or corrupted store files |
| **audit** (daily) | running Nix version, daemon trust, the live firewall rules, exposed ports, Docker-published ports, SSH password login, extra UID-0 users, `/etc/ld.so.preload`, new setuid files, new unmanaged `/etc` files, new or changed start-up files (autostart, shell rc, fish functions, git config, compositor configs, `~/.local/bin`, systemd user units, SSH keys, cron) | silent persistence, new exposure, rules that went missing |

## Use

```nix
inputs.nix-protect-barrior.url = "github:zenmastercat/Nix-Protect-Barrior";

# in a NixOS module
imports = [ inputs.nix-protect-barrior.nixosModules.default ];
security.nixProtectBarrior = {
  enable = true;
  build.allowedSubstituters = [ "https://cache.nixos.org" ];
  build.allowedPublicKeys = [ "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=" ];
  network.closeSsh = true;            # SSH only from this PC
  network.localOnly.tcp = [ 11434 ];  # e.g. Ollama
  network.dockerLocalOnly = true;
};
nix.package = pkgs.nixVersions.nix_2_34;  # needs >= 2.34.9 / 2.35.3 (CVE-2026-110450)
```

Every option is in `module.nix`. Defaults: build, gate (with the auto-upgrade gate and short commands), runtime, verify (with repair) and audit on; network rules only for what you list.

## Commands

| Short command | Runs | When |
|---|---|---|
| `barrier-approve` | `doas npb-check approve --flake /etc/nixos` | once after installing, and after a deliberate change (new input, cache, …); shows what changes and asks you to type `APPROVE` (or `WIDEN` when trust grows) |
| `rebuild` | `doas npb-rebuild switch` | instead of `nixos-rebuild switch` |
| `rebuild-boot` | `doas npb-rebuild boot` | change active after the next boot |
| `barrier-status` | `doas npb-status` | latest audit and store check |
| `barrier-audit` | run the audit now, then the status | |
| `barrier-verify` | check (and repair) the store now, then the status | |

`npb-rebuild` takes every `nixos-rebuild` argument; `--flake` defaults to `/etc/nixos#<hostname>`. Other tools: `npb-check gate --flake DIR --host H`, `doas npb-audit --accept` (after checking new start-up files), `doas npb-verify --repair`, `journalctl -u nix-protect-barrior-audit -p warning`.

## How the gate decides

- It compares against the policy of the **running** system (`/etc/nix-protect-barrior/policy.json`) and one approval per host (root-only, `/var/lib/nix-protect-barrior/approved/<host>.json`). The approval is the same for `/etc/nixos`, a store copy and the automatic upgrade.
- Without an approval, the gate blocks. Approving needs a person at a terminal: `barrier-approve` lists every input source and every place where trust grows, and saves only after you type the word it asks for.
- Never approvable: unpinned inputs, `http://`/`git://`, sandbox off, `require-sigs` off, `accept-flake-config`, `include` lines in `nix.extraOptions`, sandbox-escaping derivations.
- Weakening a protection (for example `runtime.sysctls = false` or removing a local-only port) blocks until you approve exactly that configuration.
- **Automatic upgrade**: inputs listed with `--update-input` are updated in a temporary copy, which is frozen, gated with the full closure scan, and then built as is. If the gate blocks, nothing changes and the service fails (`systemctl status nixos-upgrade`). With `allowReboot`, NixOS's own upgrade script stays and the gate checks the current lock first.

## Limits

- Only `npb-rebuild` / `rebuild` and the automatic upgrade go through the gate. A plain `nixos-rebuild` or `nix build` as root does not.
- SSH "closed" is a firewall rule; `sshd` still listens and works from this PC.
- Docker: a container that names `0.0.0.0` in its port mapping still publishes to the network (Docker's NAT runs before the host firewall). The audit reports it, as high when the port is local-only.
- `ollamaLocalOrigins` still allows browser extensions (`moz-extension://*`, `chrome-extension://*`).
- `ptrace_scope=1`: attaching `gdb`/`py-spy` to a running process needs `doas`. `dmesg_restrict` and `kptr_restrict=2` hide kernel messages and addresses from normal users. Turn off with `runtime.restrictPtrace = false` or set your own `boot.kernel.sysctl` values.
- A non-trusted user's `nix` commands ignore caches a flake asks for (`nixConfig`); add them to `nix.settings.substituters` and the allowlist.
- The gate's evaluation runs as root; the evaluator CVE-2026-110449 is fixed by the same Nix floor.
- The store check covers the running system's closure, not every path in `/nix/store`.

## Tests

```sh
nix flake check
```

- `unit`: 23 tests of the gate rules (lock pinning and sources, caches/keys/trusted users incl. `extra-*` and `extraOptions`, protections switched off, approvals).
- `assertion-control`, `assertion`, `assertion-extra-options`, `assertion-old-nix`: a clean configuration evaluates; an unknown cache, an `extraOptions` trusted user and Nix 2.34.8 are refused.
- `vm`: a protected machine and an attacker machine. Only root is trusted; kernel settings; the attacker cannot reach a local-only port or SSH while another port stays open; the rules survive a firewall reload and a deleted rule is reported; the short commands exist; the audit reports a planted setuid file and an autostart entry; the store check passes on a clean store and finds a tampered path.

## License

MIT (see `LICENSE`).
