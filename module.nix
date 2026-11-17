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
  };

  gateFlake =
    let
      f = toString (config.system.autoUpgrade.flake or "");
    in
    lib.head (lib.splitString "#" f);
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
        description = "Run the gate before system.autoUpgrade; a blocked gate stops the upgrade.";
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
          subs = (config.nix.settings.substituters or [ ]) ++ (config.nix.settings.trusted-substituters or [ ]);
          badSubs = lib.filter (s: !(lib.elem (norm s) (map norm cfg.build.allowedSubstituters))) subs;
          badKeys = lib.filter (k: !(lib.elem k cfg.build.allowedPublicKeys)) (
            config.nix.settings.trusted-public-keys or [ ]
          );
        in
        [
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

    (mkIf (cfg.gate.enable && cfg.gate.autoUpgrade && config.system.autoUpgrade.enable) {
      systemd.services.nixos-upgrade.serviceConfig.ExecStartPre = [
        (pkgs.writeShellScript "npb-gate-autoupgrade" ''
          flake=${lib.escapeShellArg gateFlake}
          if [ -e "$flake/flake.nix" ]; then
            exec ${pkg}/bin/npb-check gate --flake "$flake" --host ${lib.escapeShellArg config.networking.hostName} --fast
          fi
          echo "npb: auto-upgrade source $flake is not a local flake folder; gate skipped" >&2
        '')
      ];
    })

    (mkIf (hasLocalOnly && !config.networking.nftables.enable) {
      networking.firewall.extraCommands = ''
        ip46tables -N npb-local-only 2>/dev/null || ip46tables -F npb-local-only
        ${lib.concatMapStrings (i: "ip46tables -A npb-local-only -i ${i} -j RETURN\n") cfg.network.localInterfaces}
        ip46tables -A npb-local-only -j nixos-fw-refuse
        ${lib.concatMapStrings (r: "ip46tables -I nixos-fw 1 ${r} -j npb-local-only\n") rules}
      '';
      networking.firewall.extraStopCommands = ''
        ${lib.concatMapStrings (r: "ip46tables -D nixos-fw ${r} -j npb-local-only 2>/dev/null || true\n") rules}
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
      virtualisation.docker.daemon.settings.ip = "127.0.0.1";
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
