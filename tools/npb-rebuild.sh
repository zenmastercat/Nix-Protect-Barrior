# npb-rebuild: nixos-rebuild behind the Nix-Protect-Barrior build gate.
# Same arguments as nixos-rebuild. For build/boot/switch/test/dry-*, it runs
# `npb-check gate` on the flake first and stops if the gate blocks.
#   --npb-approve   approve the flake's current inputs/caches first (root)
#   --npb-fast      skip the closure scan
set -euo pipefail

approve=0
fast=()
args=()
for a in "$@"; do
  case "$a" in
    --npb-approve) approve=1 ;;
    --npb-fast) fast=(--fast) ;;
    *) args+=("$a") ;;
  esac
done

action="${args[0]:-}"
flake="/etc/nixos"
host="$(hostname)"
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    --flake) ref="${args[$((i + 1))]:-}" ;;
    --flake=*) ref="${args[$i]#--flake=}" ;;
    *) continue ;;
  esac
  flake="${ref%%#*}"
  [[ "$ref" == *"#"* ]] && host="${ref#*#}"
done

case "$action" in
  build | boot | switch | test | dry-build | dry-activate | build-vm)
    if [[ ! -e "$flake/flake.nix" ]]; then
      echo "npb-rebuild: only local flake folders can be checked ($flake)" >&2
      exit 2
    fi
    if ((approve)); then
      npb-check approve --flake "$flake" --host "$host"
    fi
    echo "npb-rebuild: checking $flake#$host before '$action'..."
    if ! npb-check gate --flake "$flake" --host "$host" "${fast[@]}"; then
      echo "npb-rebuild: blocked by Nix-Protect-Barrior; nothing was built." >&2
      exit 1
    fi
    ;;
esac

exec nixos-rebuild "${args[@]}"
