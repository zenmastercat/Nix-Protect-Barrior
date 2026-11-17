# npb-rebuild: nixos-rebuild behind the Nix-Protect-Barrior build gate.
# Same arguments as nixos-rebuild; --flake defaults to /etc/nixos#<hostname>.
# For build/boot/switch/test/dry-*, the flake is first copied into the Nix
# store once; the gate checks that copy and nixos-rebuild builds the same
# copy, so nothing can change in between.
#   --npb-fast   skip the closure scan
set -euo pipefail

fast=()
args=()
for a in "$@"; do
  case "$a" in
    --npb-fast) fast=(--fast) ;;
    --npb-approve)
      echo "npb-rebuild: approvals are separate on purpose: run 'doas npb-check approve' first" >&2
      exit 2
      ;;
    *) args+=("$a") ;;
  esac
done

action="${args[0]:-}"
flake="/etc/nixos"
host="$(hostname)"
flake_idx=-1
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    --flake) ref="${args[$((i + 1))]:-}"; flake_idx=$((i + 1)) ;;
    --flake=*) ref="${args[$i]#--flake=}"; flake_idx=$i ;;
    *) continue ;;
  esac
  flake="${ref%%#*}"
  [[ "$ref" == *"#"* ]] && host="${ref#*#}"
done

case "$action" in
  build | boot | switch | test | dry-build | dry-activate | build-vm) ;;
  *) exec nixos-rebuild "${args[@]}" ;;
esac

if [[ ! -e "$flake/flake.nix" ]]; then
  echo "npb-rebuild: only local flake folders can be checked ($flake)" >&2
  exit 2
fi

echo "npb-rebuild: freezing $flake into the store..."
frozen="$(npb-check archive --flake "$flake")"
echo "npb-rebuild: checking $frozen#$host before '$action'..."
if ! npb-check gate --flake "$frozen" --host "$host" "${fast[@]}"; then
  echo "npb-rebuild: blocked by Nix-Protect-Barrior; nothing was built." >&2
  exit 1
fi

if ((flake_idx < 0)); then
  args+=(--flake "$frozen#$host")
elif [[ "${args[$flake_idx]}" == --flake=* ]]; then
  args[flake_idx]="--flake=$frozen#$host"
else
  args[flake_idx]="$frozen#$host"
fi
exec nixos-rebuild "${args[@]}"
