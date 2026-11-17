# Nix-Protect-Barrior: a security layer for a NixOS desktop.
#
#   build    the Nix daemon: no root through trusted-users, strict sandbox,
#            signed caches only, caches and keys from an allowlist
#   gate     npb-check / npb-rebuild: check a flake before it is built
#            (also in front of system.autoUpgrade)
#   network  ports that only this PC and its containers may reach, SSH closed
#            to the network, Docker publishing on 127.0.0.1, Ollama origins
#   runtime  kernel settings that block common attack steps
#   verify   weekly store integrity check, repairing tampered paths
#   audit    daily audit of daemon trust, exposure, setuid files, persistence
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.security.nixProtectBarrior;
  inherit (lib)
    mkOption
    mkEnableOption
    mkIf
    mkMerge
    mkDefault
    mkForce
    types
    ;

  stateDir = "/var/lib/nix-protect-barrior";
  pkg = cfg.package;

  norm = u: lib.toLower (lib.removeSuffix "/" u);

  portRange = types.submodule {
    options = {
      from = mkOption { type = types.port; };
      to = mkOption { type = types.port; };
    };
  };

  lo = cfg.network.localOnly;
  sshPorts = lib.optionals (cfg.network.closeSsh && config.services.openssh.enable) config.services.openssh.ports;
  tcpPorts = lib.unique (lo.tcp ++ sshPorts);
  hasLocalOnly = tcpPorts != [ ] || lo.udp != [ ] || lo.tcpRanges != [ ] || lo.udpRanges != [ ];

  dport = p: if builtins.isInt p then toString p else "${toString p.from}:${toString p.to}";
  rules =
    (map (p: "-p tcp --dport ${dport p}") (tcpPorts ++ lo.tcpRanges))
    ++ (map (p: "-p udp --dport ${dport p}") (lo.udp ++ lo.udpRanges));

  nftPorts = ps: rs: lib.concatStringsSep ", " (map toString ps ++ map (r: "${toString r.from}-${toString r.to}") rs);
  nftIfaces = lib.concatMapStrings (i: '' iifname != "${lib.replaceStrings [ "+" ] [ "*" ] i}"'') cfg.network.localInterfaces;

  watchUsers = lib.mapAttrsToList (name: u: { inherit name; inherit (u) home; }) (
    lib.filterAttrs (_: u: u.isNormalUser) config.users.users
  );

  fw = config.networking.firewall;
  policy = {
    enabled = true;
    inherit stateDir watchUsers;
    allowedSubstituters = cfg.build.allowedSubstituters;
    trustedPublicKeys = cfg.build.allowedPublicKeys;
    trustedUsers = cfg.build.trustedUsers;
    permittedInsecure = config.nixpkgs.config.permittedInsecurePackages or [ ];
    localOnly = {
      tcp = tcpPorts;
      inherit (lo) udp tcpRanges udpRanges;
    };
    firewall = {
      inherit (fw)
        enable
        allowedTCPPorts
        allowedUDPPorts
        allowedTCPPortRanges
        allowedUDPPortRanges
        ;
    };
    ssh = {
      inherit (config.services.openssh) enable ports;
      passwordAuth = config.services.openssh.settings.PasswordAuthentication or true;
      closed = cfg.network.closeSsh;
    };
    nftables = config.networking.nftables.enable;
    inherit nixFloors;
    # Snapshot of every switch; the gate fails when a new configuration weakens one.
    hardening = {
      barrier = true;
      buildEnable = cfg.build.enable;
      gateEnable = cfg.gate.enable;
      gateAutoUpgrade = cfg.gate.autoUpgrade;
      sysctls = cfg.runtime.sysctls;
      restrictPtrace = cfg.runtime.restrictPtrace;
      closeSsh = cfg.network.closeSsh;
      dockerLocalOnly = cfg.network.dockerLocalOnly;
      ollamaLocalOrigins = cfg.network.ollamaLocalOrigins;
      verify = cfg.verify.enable;
      autoRepair = cfg.verify.autoRepair;
      audit = cfg.audit.enable;
      localTcp = lo.tcp;
      localUdp = lo.udp;
      localTcpRanges = map (r: "${toString r.from}-${toString r.to}") lo.tcpRanges;
      localUdpRanges = map (r: "${toString r.from}-${toString r.to}") lo.udpRanges;
    };
  };

  # Auto-upgrade: update inputs in a temporary copy, freeze it, gate it fully,
  # then build exactly that frozen copy.
  au = config.system.autoUpgrade;
  auRef = toString (au.flake or "");
  auFlake = lib.head (lib.splitString "#" auRef);
  auHost =
    let
      parts = lib.splitString "#" auRef;
    in
    if lib.length parts > 1 then lib.elemAt parts 1 else config.networking.hostName;
  auFlags = lib.filter (f: !(lib.hasPrefix "--flake" f)) au.flags;
  auUpdates =
    lib.concatLists (
      lib.imap0 (
        i: f: lib.optional (f == "--update-input" && i + 1 < lib.length auFlags) (lib.elemAt auFlags (i + 1))
      ) auFlags
    );
  auRecreate = lib.elem "--recreate-lock-file" auFlags;
  auKeep =
    let
      drop = [ "--refresh" "--recreate-lock-file" "--no-write-lock-file" ];
      go =
        acc: rest:
        if rest == [ ] then
          acc
        else if lib.head rest == "--update-input" then
          go acc (lib.drop 2 rest)
        else if lib.elem (lib.head rest) drop then
          go acc (lib.tail rest)
        else
          go (acc ++ [ (lib.head rest) ]) (lib.tail rest);
    in
    go [ ] auFlags;
  gatedUpgrade = pkgs.writeShellScript "npb-gated-upgrade" ''
    set -euo pipefail
    src="$(${pkg}/bin/npb-check archive --flake ${lib.escapeShellArg auFlake})"
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    mkdir "$work/flake"
    cp -r --no-preserve=mode,ownership "$src"/. "$work/flake"/
    ${lib.optionalString auRecreate ''nix flake update --flake "path:$work/flake"''}
    ${lib.concatMapStrings (i: ''nix flake update ${lib.escapeShellArg i} --flake "path:$work/flake"
    '') auUpdates}
    frozen="$(${pkg}/bin/npb-check archive --flake "path:$work/flake")"
    echo "npb: gating auto-upgrade of $frozen#${auHost}"
    ${pkg}/bin/npb-check gate --flake "$frozen" --host ${lib.escapeShellArg auHost}
    exec ${config.system.build.nixos-rebuild}/bin/nixos-rebuild ${au.operation} \
      --flake "$frozen#${auHost}" ${lib.escapeShellArgs auKeep}
  '';

  sudo = if config.security.doas.enable then "doas" else "sudo";

  # First patched release per series for the Nix daemon CVEs of 2026-10-13
  # (CVE-2026-110450: unprivileged clients can corrupt store paths via the
  # repair flag -> root; plus CVE-2026-110449/-110452/-110453).
  nixFloors = {
    "2.28" = "2.28.8";
    "2.30" = "2.30.6";
    "2.31" = "2.31.6";
    "2.34" = "2.34.9";
    "2.35" = "2.35.3";
  };
  nixPatched =
    v:
    let
      series = lib.versions.majorMinor v;
    in
    if nixFloors ? ${series} then
      lib.versionAtLeast v nixFloors.${series}
    else
      lib.versionAtLeast v "2.36";

in
{
  options.security.nixProtectBarrior = {
    enable = mkEnableOption "Nix-Protect-Barrior";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { nix = config.nix.package; };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = "The npb-* tools.";
    };

    build = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Harden the Nix daemon.";
      };
      trustedUsers = mkOption {
        type = types.listOf types.str;
        default = [ "root" ];
        description = ''
          Users the Nix daemon fully trusts. A trusted user can add caches and
          keys or turn the sandbox off for its builds, which equals root.
        '';
      };
      requirePatchedNix = mkOption {
        type = types.bool;
        default = true;
        description = "Refuse a Nix version with known daemon vulnerabilities (see nixFloors in module.nix).";
      };
      allowedUsers = mkOption {
        type = types.listOf types.str;
        default = [
          "root"
          "@wheel"
        ];
        description = "Users that may talk to the Nix daemon at all.";
      };
      allowedSubstituters = mkOption {
        type = types.listOf types.str;
        default = [ "https://cache.nixos.org" ];
        description = "Binary caches the configuration may use. Others fail the build.";
      };
      allowedPublicKeys = mkOption {
        type = types.listOf types.str;
        default = [ "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=" ];
        description = "Cache signing keys the configuration may trust. Others fail the build.";
      };
    };

    gate = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Install npb-check and npb-rebuild (nixos-rebuild behind the build gate).";
      };
      autoUpgrade = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Gate system.autoUpgrade: inputs are updated in a temporary copy, which is
          frozen, fully gated (closure scan included) and then built as is. A
          blocked gate stops the upgrade.
        '';
      };
      aliases = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Short shell commands: rebuild, rebuild-boot, barrier-status,
          barrier-approve, barrier-audit, barrier-verify.
        '';
      };
    };

    network = {
      localOnly = {
        tcp = mkOption {
          type = types.listOf types.port;
          default = [ ];
          description = "TCP ports only this PC and its local interfaces may reach, even if opened elsewhere.";
        };
        udp = mkOption {
          type = types.listOf types.port;
          default = [ ];
        };
        tcpRanges = mkOption {
          type = types.listOf portRange;
          default = [ ];
        };
        udpRanges = mkOption {
          type = types.listOf portRange;
          default = [ ];
        };
      };
      localInterfaces = mkOption {
        type = types.listOf types.str;
        default = [
          "lo"
          "docker+"
          "br-+"
        ];
        description = "Interfaces still allowed to reach local-only ports (iptables wildcard syntax).";
      };
      closeSsh = mkOption {
        type = types.bool;
        default = false;
        description = "Make the SSH ports local-only (SSH stays usable from this PC).";
      };
      dockerLocalOnly = mkOption {
        type = types.bool;
        default = false;
        description = "Docker publishes container ports on 127.0.0.1 unless a container names an address.";
      };
      ollamaLocalOrigins = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Replace OLLAMA_ORIGINS with browser-extension origins only (Ollama always
          allows localhost), so web pages cannot call the local Ollama API.
        '';
      };
    };

    runtime = {
      sysctls = mkOption {
        type = types.bool;
        default = true;
        description = "Kernel settings that block common attack steps (your own explicit values win).";
      };
      restrictPtrace = mkOption {
        type = types.bool;
        default = true;
        description = ''
          kernel.yama.ptrace_scope = 1: a program can only debug its own children.
          Attaching gdb or py-spy to a running process then needs doas.
        '';
      };
    };

    verify = {
      enable = mkOption {
        type = types.bool;
        default = true;
      };
      schedule = mkOption {
        type = types.str;
        default = "Sun 03:30";
      };
      autoRepair = mkOption {
        type = types.bool;
        default = true;
        description = "Replace store paths that changed on disk with a verified copy.";
      };
    };

    audit = {
      enable = mkOption {
        type = types.bool;
        default = true;
      };
      schedule = mkOption {
        type = types.str;
        default = "*-*-* 05:30";
      };
    };
  };

  config = mkIf cfg.enable (mkMerge [
    {
      assertions = [
        {
          assertion = !hasLocalOnly || config.networking.firewall.enable;
          message = "Nix-Protect-Barrior: local-only ports need networking.firewall.enable = true.";
        }
      ];
      environment.systemPackages = [ pkg ];
      environment.etc."nix-protect-barrior/policy.json".text = builtins.toJSON policy;
      systemd.tmpfiles.rules = [ "d ${stateDir} 0700 root root -" ];
    }

    (mkIf cfg.build.enable {
      nix.settings = {
        sandbox = mkForce true;
        sandbox-fallback = mkForce false;
        require-sigs = mkForce true;
        trusted-users = mkForce cfg.build.trustedUsers;
        allowed-users = mkDefault cfg.build.allowedUsers;
      };
      assertions =
        let
          ns = config.nix.settings;
          subs =
            (ns.substituters or [ ])
            ++ (ns.extra-substituters or [ ])
            ++ (ns.trusted-substituters or [ ])
            ++ (ns.extra-trusted-substituters or [ ]);
          badSubs = lib.filter (s: !(lib.elem (norm s) (map norm cfg.build.allowedSubstituters))) subs;
          badKeys = lib.filter (k: !(lib.elem k cfg.build.allowedPublicKeys)) (
            (ns.trusted-public-keys or [ ]) ++ (ns.extra-trusted-public-keys or [ ])
          );
          badTrusted = lib.filter (u: !(lib.elem u cfg.build.trustedUsers)) (ns.extra-trusted-users or [ ]);
          # nix.extraOptions is appended to nix.conf verbatim: it may not set trust.
          trustKey = "(extra-)?(substituters|trusted-substituters|trusted-public-keys|trusted-users|allowed-users|sandbox|sandbox-fallback|require-sigs|accept-flake-config)";
          badExtra = lib.filter (
            l: builtins.match "[[:space:]]*(${trustKey}[[:space:]]*=.*|!?include[[:space:]].*)" l != null
          ) (lib.splitString "\n" config.nix.extraOptions);
        in
        [
          {
            assertion = !cfg.build.requirePatchedNix || nixPatched config.nix.package.version;
            message = "Nix-Protect-Barrior: Nix ${config.nix.package.version} has known daemon vulnerabilities (CVE-2026-110450: any daemon user can get root). Use a patched Nix, e.g. nix.package = pkgs.nixVersions.nix_2_34 (>= 2.34.9) or nixVersions.latest (>= 2.35.3).";
          }
          {
            assertion = badTrusted == [ ];
            message = "Nix-Protect-Barrior: extra-trusted-users would make these users root-equivalent: ${lib.concatStringsSep ", " badTrusted}";
          }
          {
            assertion = badExtra == [ ];
            message = "Nix-Protect-Barrior: nix.extraOptions may not set trust or include files; use nix.settings: ${lib.concatStringsSep " | " badExtra}";
          }
          {
            assertion = badSubs == [ ];
            message = "Nix-Protect-Barrior: binary caches outside security.nixProtectBarrior.build.allowedSubstituters: ${lib.concatStringsSep ", " badSubs}";
          }
          {
            # Off by default; only valid with flakes, so it is checked, not set.
            assertion = !(config.nix.settings.accept-flake-config or false);
            message = "Nix-Protect-Barrior: nix.settings.accept-flake-config lets any flake add caches and settings; turn it off.";
          }
          {
            assertion = badKeys == [ ];
            message = "Nix-Protect-Barrior: cache signing keys outside security.nixProtectBarrior.build.allowedPublicKeys: ${lib.concatStringsSep ", " badKeys}";
          }
        ];
    })

    (mkIf (cfg.gate.enable && cfg.gate.autoUpgrade && au.enable && au.flake != null && !au.allowReboot) {
      systemd.services.nixos-upgrade.path = [ pkg ];
      systemd.services.nixos-upgrade.script = mkForce "exec ${gatedUpgrade}";
    })

    (mkIf (cfg.gate.enable && cfg.gate.autoUpgrade && au.enable && au.flake != null && au.allowReboot) {
      # With reboots, NixOS's own upgrade script stays; the gate runs first on the
      # current lock (input updates happen afterwards, inside nixos-rebuild).
      systemd.services.nixos-upgrade.serviceConfig.ExecStartPre = [
        "${pkg}/bin/npb-check gate --flake ${lib.escapeShellArg auFlake} --host ${lib.escapeShellArg auHost}"
      ];
    })

    (mkIf (cfg.gate.enable && cfg.gate.aliases) {
      environment.shellAliases = {
        rebuild = "${sudo} npb-rebuild switch";
        rebuild-boot = "${sudo} npb-rebuild boot";
        barrier-status = "${sudo} npb-status";
        barrier-approve = "${sudo} npb-check approve --flake /etc/nixos";
        barrier-audit = "${sudo} systemctl start nix-protect-barrior-audit.service; ${sudo} npb-status";
        barrier-verify = "${sudo} systemctl start nix-protect-barrior-verify.service; ${sudo} npb-status";
      };
    })

    (mkIf (hasLocalOnly && !config.networking.nftables.enable) {
      networking.firewall.extraCommands = ''
        ip46tables -N npb-local-only 2>/dev/null || ip46tables -F npb-local-only
        ${lib.concatMapStrings (i: "ip46tables -A npb-local-only -i ${i} -j RETURN\n") cfg.network.localInterfaces}
        ip46tables -A npb-local-only -j nixos-fw-refuse
        ${lib.concatMapStrings (r: "while ip46tables -D nixos-fw ${r} -j npb-local-only 2>/dev/null; do :; done\nip46tables -I nixos-fw 1 ${r} -j npb-local-only\n") rules}
      '';
      networking.firewall.extraStopCommands = ''
        ${lib.concatMapStrings (r: "while ip46tables -D nixos-fw ${r} -j npb-local-only 2>/dev/null; do :; done\n") rules}
        ip46tables -F npb-local-only 2>/dev/null || true
        ip46tables -X npb-local-only 2>/dev/null || true
      '';
    })

    (mkIf (hasLocalOnly && config.networking.nftables.enable) {
      networking.nftables.tables.npb = {
        family = "inet";
        content = ''
          chain input {
            type filter hook input priority filter - 5; policy accept;
            ${lib.optionalString (tcpPorts != [ ] || lo.tcpRanges != [ ])
              "tcp dport { ${nftPorts tcpPorts lo.tcpRanges} }${nftIfaces} drop"}
            ${lib.optionalString (lo.udp != [ ] || lo.udpRanges != [ ])
              "udp dport { ${nftPorts lo.udp lo.udpRanges} }${nftIfaces} drop"}
          }
        '';
      };
    })

    (mkIf cfg.network.dockerLocalOnly {
      virtualisation.docker.daemon.settings = {
        # default bridge
        ip = "127.0.0.1";
        # every new user-defined network (docker compose)
        default-network-opts.bridge."com.docker.network.bridge.host_binding_ipv4" = "127.0.0.1";
      };
    })

    (mkIf cfg.network.ollamaLocalOrigins {
      services.ollama.environmentVariables.OLLAMA_ORIGINS = mkForce "moz-extension://*,chrome-extension://*";
    })

    (mkIf cfg.runtime.sysctls {
      # Priority 900: above NixOS's own mkDefault values, below anything set explicitly.
      boot.kernel.sysctl = lib.mapAttrs (_: lib.mkOverride 900) (
        {
          "kernel.dmesg_restrict" = 1;
          "kernel.kptr_restrict" = 2;
          "kernel.unprivileged_bpf_disabled" = 1;
          "net.core.bpf_jit_harden" = 2;
          "kernel.kexec_load_disabled" = 1;
          "dev.tty.ldisc_autoload" = 0;
          "fs.protected_fifos" = 2;
          "fs.protected_regular" = 2;
          "fs.protected_symlinks" = 1;
          "fs.protected_hardlinks" = 1;
          "fs.suid_dumpable" = 0;
          "net.ipv4.tcp_syncookies" = 1;
          "net.ipv4.icmp_echo_ignore_broadcasts" = 1;
          "net.ipv4.conf.all.accept_redirects" = 0;
          "net.ipv4.conf.default.accept_redirects" = 0;
          "net.ipv4.conf.all.secure_redirects" = 0;
          "net.ipv4.conf.default.secure_redirects" = 0;
          "net.ipv4.conf.all.send_redirects" = 0;
          "net.ipv4.conf.default.send_redirects" = 0;
          "net.ipv6.conf.all.accept_redirects" = 0;
          "net.ipv6.conf.default.accept_redirects" = 0;
          "net.ipv4.conf.all.accept_source_route" = 0;
          "net.ipv6.conf.all.accept_source_route" = 0;
        }
        // lib.optionalAttrs cfg.runtime.restrictPtrace { "kernel.yama.ptrace_scope" = 1; }
      );
    })

    (mkIf cfg.verify.enable {
      systemd.services.nix-protect-barrior-verify = {
        description = "Nix-Protect-Barrior: verify (and repair) the system's store paths";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkg}/bin/npb-verify${lib.optionalString cfg.verify.autoRepair " --repair"}";
          Nice = 19;
          IOSchedulingClass = "idle";
          CPUSchedulingPolicy = "idle";
        };
      };
      systemd.timers.nix-protect-barrior-verify = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = cfg.verify.schedule;
          Persistent = true;
          RandomizedDelaySec = "30min";
        };
      };
    })

    (mkIf cfg.audit.enable {
      systemd.services.nix-protect-barrior-audit = {
        description = "Nix-Protect-Barrior: daily security audit";
        after = [ "network.target" "firewall.service" "docker.service" ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkg}/bin/npb-audit";
          Nice = 10;
          IOSchedulingClass = "idle";
        };
      };
      systemd.timers.nix-protect-barrior-audit = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = cfg.audit.schedule;
          OnBootSec = "15min";
          Persistent = true;
          RandomizedDelaySec = "20min";
        };
      };
    })
  ]);
}
