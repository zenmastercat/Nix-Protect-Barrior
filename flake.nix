{
  description = "Nix-Protect-Barrior: build gate, daemon hardening, network barrier and repair/audit services for NixOS";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      lib = nixpkgs.lib;
    in
    {
      nixosModules.default = ./module.nix;
      nixosModules.nix-protect-barrior = ./module.nix;

      packages.${system}.default = pkgs.callPackage ./package.nix { };

      checks.${system} = {
        # Gate logic (flake.lock / policy / closure rules) on fixtures.
        unit = pkgs.runCommand "npb-unit-tests" { nativeBuildInputs = [ pkgs.python3 ]; } ''
          cp -r ${./tools} tools; cp -r ${./tests} tests
          NPB_TOOLS=$PWD/tools python3 -I tests/test_gate.py -v
          touch $out
        '';

        # Control: a clean configuration with the barrier evaluates (so the
        # assertion tests below fail for the right reason).
        assertion-control =
          let
            ok = lib.nixosSystem {
              inherit system;
              modules = [
                self.nixosModules.default
                {
                  security.nixProtectBarrior.enable = true;
                  nix.extraOptions = "keep-outputs = true";
                  boot.loader.grub.enable = false;
                  fileSystems."/" = {
                    device = "none";
                    fsType = "tmpfs";
                  };
                  system.stateVersion = "26.05";
                }
              ];
            };
          in
          assert (builtins.tryEval ok.config.system.build.toplevel.drvPath).success;
          pkgs.runCommand "npb-assertion-control" { } "touch $out";

        # The module refuses an untrusted binary cache at evaluation time.
        assertion =
          let
            bad = lib.nixosSystem {
              inherit system;
              modules = [
                self.nixosModules.default
                {
                  security.nixProtectBarrior.enable = true;
                  nix.settings.substituters = [ "https://evil.example.org" ];
                  boot.loader.grub.enable = false;
                  fileSystems."/" = {
                    device = "none";
                    fsType = "tmpfs";
                  };
                  system.stateVersion = "26.05";
                }
              ];
            };
            r = builtins.tryEval bad.config.system.build.toplevel.drvPath;
          in
          assert !r.success;
          pkgs.runCommand "npb-assertion-test" { } "touch $out";

        # nix.extraOptions cannot sneak in a trusted user or cache.
        assertion-extra-options =
          let
            bad = lib.nixosSystem {
              inherit system;
              modules = [
                self.nixosModules.default
                {
                  security.nixProtectBarrior.enable = true;
                  nix.extraOptions = "extra-trusted-users = mallory";
                  boot.loader.grub.enable = false;
                  fileSystems."/" = {
                    device = "none";
                    fsType = "tmpfs";
                  };
                  system.stateVersion = "26.05";
                }
              ];
            };
            r = builtins.tryEval bad.config.system.build.toplevel.drvPath;
          in
          assert !r.success;
          pkgs.runCommand "npb-assertion-extra-options-test" { } "touch $out";

        # A Nix with known daemon CVEs (CVE-2026-110450) is refused.
        assertion-old-nix =
          let
            bad = lib.nixosSystem {
              inherit system;
              modules = [
                self.nixosModules.default
                {
                  security.nixProtectBarrior.enable = true;
                  nix.package = pkgs.nix // { version = "2.34.8"; };
                  boot.loader.grub.enable = false;
                  fileSystems."/" = {
                    device = "none";
                    fsType = "tmpfs";
                  };
                  system.stateVersion = "26.05";
                }
              ];
            };
          in
          assert !(builtins.tryEval bad.config.system.build.toplevel.drvPath).success;
          pkgs.runCommand "npb-assertion-old-nix-test" { } "touch $out";

        # Two machines: the attacker on the LAN cannot reach local-only ports or
        # SSH; trust, sysctls, audit findings and store-tamper detection work.
        vm = pkgs.testers.runNixOSTest (import ./tests/vm.nix { module = self.nixosModules.default; });
      };

      formatter.${system} = pkgs.nixfmt-rfc-style;
    };
}
