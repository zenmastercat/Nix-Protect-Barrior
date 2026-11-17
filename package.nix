{
  lib,
  stdenvNoCC,
  makeWrapper,
  python3,
  bash,
  nix,
  iproute2,
  iptables,
  nftables,
  findutils,
  coreutils,
  hostname,
}:
stdenvNoCC.mkDerivation {
  pname = "nix-protect-barrior";
  version = "0.1.0";
  src = ./tools;
  nativeBuildInputs = [ makeWrapper ];
  dontBuild = true;
  installPhase = ''
    runHook preInstall
    mkdir -p $out/bin $out/libexec/npb
    cp npb_*.py npb-rebuild.sh $out/libexec/npb/
    for t in check audit verify status; do
      makeWrapper ${python3}/bin/python3 $out/bin/npb-$t \
        --add-flags "-I $out/libexec/npb/npb_$t.py" \
        --prefix PATH : ${lib.makeBinPath [ nix iproute2 iptables nftables findutils coreutils ]}
    done
    makeWrapper ${bash}/bin/bash $out/bin/npb-rebuild \
      --add-flags $out/libexec/npb/npb-rebuild.sh \
      --prefix PATH : $out/bin:${lib.makeBinPath [ coreutils hostname ]} \
      --suffix PATH : /run/current-system/sw/bin
    runHook postInstall
  '';
  meta = {
    description = "Build gate, audit and store repair tools of Nix-Protect-Barrior";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "npb-check";
  };
}
