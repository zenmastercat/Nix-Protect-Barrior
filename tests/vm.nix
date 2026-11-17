{ module }:
{
  name = "nix-protect-barrior";

  nodes = {
    pc =
      { pkgs, ... }:
      {
        imports = [ module ];
        security.nixProtectBarrior = {
          enable = true;
          network.localOnly.tcp = [ 11434 ];
          network.closeSsh = true;
          verify.autoRepair = false;
        };
        # What a careless config might contain: the barrier must override it.
        nix.settings.trusted-users = [
          "root"
          "alice"
        ];
        users.users.alice.isNormalUser = true;
        # Test only: let the script tamper with a store path (copy-up into the VM overlay).
        virtualisation.writableStore = true;
        boot.nixStoreMountOpts = [
          "nodev"
          "nosuid"
        ];
        services.openssh.enable = true;
        networking.firewall.allowedTCPPorts = [
          11434
          8080
        ];
        environment.systemPackages = [
          pkgs.hello
          pkgs.curl
          pkgs.netcat
        ];
        systemd.services.fake-ollama = {
          wantedBy = [ "multi-user.target" ];
          serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 11434 --bind 0.0.0.0";
        };
        systemd.services.web = {
          wantedBy = [ "multi-user.target" ];
          serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8080 --bind 0.0.0.0";
        };
      };
    attacker =
      { pkgs, ... }:
      {
        environment.systemPackages = [
          pkgs.curl
          pkgs.netcat
        ];
      };
  };

  testScript = ''
    import json
    start_all()
    pc.wait_for_unit("multi-user.target")
    pc.wait_for_open_port(11434)
    pc.wait_for_open_port(8080)
    pc.wait_for_unit("sshd.service")
    attacker.wait_for_unit("multi-user.target")

    with subtest("build barrier: only root is a trusted Nix user, sandbox and signatures on"):
        out = pc.succeed("nix --extra-experimental-features nix-command config show")
        assert "trusted-users = root\n" in out, out
        assert "sandbox = true\n" in out
        assert "require-sigs = true\n" in out
        assert "accept-flake-config = true" not in out

    with subtest("runtime barrier: kernel settings"):
        assert pc.succeed("sysctl -n kernel.yama.ptrace_scope").strip() == "1"
        assert pc.succeed("sysctl -n kernel.dmesg_restrict").strip() == "1"
        assert pc.succeed("sysctl -n kernel.kptr_restrict").strip() == "2"

    with subtest("network barrier: local-only port and SSH closed to the LAN, other ports untouched"):
        pc.succeed("curl -sf http://127.0.0.1:11434/ >/dev/null")
        attacker.fail("curl -sf --max-time 5 http://pc:11434/")
        attacker.fail("nc -z -w 3 pc 22")
        attacker.succeed("curl -sf --max-time 5 http://pc:8080/ >/dev/null")
        pc.succeed("nc -z -w 3 127.0.0.1 22")

    with subtest("audit: baseline, then a planted setuid file and autostart entry are reported"):
        pc.succeed("systemctl start nix-protect-barrior-audit.service")
        pc.succeed("install -m 4755 $(readlink -f /run/current-system/sw/bin/hello) /root/planted-suid")
        pc.succeed("mkdir -p /home/alice/.config/autostart && echo '[Desktop Entry]' > /home/alice/.config/autostart/x.desktop")
        pc.succeed("systemctl start nix-protect-barrior-audit.service")
        rep = json.loads(pc.succeed("cat /var/lib/nix-protect-barrior/audit-latest.json"))
        msgs = [f["message"] for f in rep["findings"]]
        assert any("/root/planted-suid" in m for m in msgs), msgs
        assert any("x.desktop" in m for m in msgs), msgs
        assert rep["counts"]["high"] >= 1, rep["counts"]
        pc.fail("npb-status > /tmp/status")  # exits 1 while high findings exist
        pc.succeed("grep -q planted-suid /tmp/status")

    with subtest("verify: clean store passes, a tampered store path is found"):
        pc.succeed("systemctl start nix-protect-barrior-verify.service")
        ok = json.loads(pc.succeed("cat /var/lib/nix-protect-barrior/verify-latest.json"))
        assert ok["ok"], ok
        hello = pc.succeed("readlink -f $(command -v hello)").strip()
        pc.succeed(f"echo tampered >> {hello}")
        pc.fail("npb-verify /run/current-system")
        bad = json.loads(pc.succeed("cat /var/lib/nix-protect-barrior/verify-latest.json"))
        assert any("hello" in p for p in bad["modified"]), bad
  '';
}
