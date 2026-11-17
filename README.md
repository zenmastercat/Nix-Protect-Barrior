# Nix-Protect-Barrior

A security layer for a NixOS desktop. It puts a gate in front of every build, closes the usual ways into a NixOS PC, and runs services that find and repair problems.

| Layer | What it does | Stops |
|---|---|---|
| **build** | Nix daemon: only `root` is a trusted user, strict sandbox, `require-sigs`, binary caches and signing keys from an allowlist (the build fails on any other) | a user-level program getting root through the daemon; poisoned or unknown caches; fake signing keys |
| **gate** | `npb-check` / `npb-rebuild`: checks a flake **before** it is built; also runs in front of `system.autoUpgrade` | unpinned or `http://` inputs; inputs from a source you never approved; new caches, keys or trusted users; sandbox or signatures turned off; newly permitted insecure packages; turning the barrier off; derivations that ask to leave the sandbox (`__noChroot`, `__impure`) |
| **network** | local-only ports (only this PC, Docker bridges and `lo`), SSH closed to the network, Docker publishing on `127.0.0.1`, Ollama origins limited | LAN access to unauthenticated services (Ollama API, relays), SSH password guessing, Docker bypassing the NixOS firewall, web pages calling a local LLM API |
| **runtime** | kernel settings (`ptrace_scope=1`, `dmesg_restrict`, `kptr_restrict=2`, no unprivileged BPF, no kexec, protected links/FIFOs, no ICMP redirects, …) | common steps after a break-in: reading other processes' memory, kernel address leaks, swapping the kernel |
| **verify** (weekly) | re-hashes every store path of the running system and the boot profile; repairs changed ones with a copy from a signed cache or a rebuild | tampered or corrupted store files |
| **audit** (daily) | daemon trust, exposed ports, Docker-published ports, SSH password login, extra UID-0 users, `/etc/ld.so.preload`, new setuid files, new unmanaged `/etc` files, new or changed start-up files (autostart, shell rc, systemd user units, SSH keys, cron) | silent persistence and new exposure |

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
```

Every option is in `module.nix`. Defaults: build, gate, runtime, verify (with repair) and audit on; network rules only for what you list.

## Commands

```sh
doas npb-rebuild switch --flake /etc/nixos#host   # nixos-rebuild behind the gate
npb-check gate --flake /etc/nixos --host host     # only the check (exit 0 pass, 1 blocked)
doas npb-check approve --flake /etc/nixos --host host   # accept deliberate changes (new input, cache, ...)
doas npb-status                                   # latest audit + store check
doas npb-audit --accept                           # after checking new start-up files: make them the baseline
doas npb-verify --repair                          # store check now
journalctl -u nix-protect-barrior-audit -p warning
```

The first gate run on a flake approves its current inputs as the baseline. After that, a new input source, cache, key, trusted user or insecure package blocks the build until you approve it. Unpinned inputs, `http://`, sandbox off, `require-sigs` off and sandbox-escaping derivations are never approvable.

The gate compares against the policy of the **running** system (`/etc/nix-protect-barrior/policy.json`). A change of the allowlist itself therefore needs one explicit approval, so an edited configuration cannot widen its own trust silently.

## Trade-offs

- `ptrace_scope=1`: attaching `gdb`/`py-spy` to a running process needs `doas` (`runtime.restrictPtrace = false` to turn off).
- A non-trusted user's `nix` commands ignore caches a flake asks for (`nixConfig`); add them to `nix.settings.substituters` and the allowlist instead.
- Docker containers that name `0.0.0.0` in their port mapping still publish to the network; the audit lists them.
- The store check covers the running system's closure, not every path in `/nix/store`.

## Tests

```sh
nix flake check   # unit tests of the gate rules, an assertion test, and a two-VM NixOS test
```

The VM test boots a protected machine and an attacker machine and checks: only root is trusted; the kernel settings; the attacker cannot reach a local-only port or SSH while another port stays open; the audit reports a planted setuid file and an autostart entry; the store check passes on a clean store and finds a tampered path.

## License

MIT (see `LICENSE`).
