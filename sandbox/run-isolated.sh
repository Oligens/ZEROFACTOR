#!/usr/bin/env bash
set -euo pipefail
usage(){ echo "Usage: run-isolated.sh --scope scope.json --target /absolute/path --image IMAGE -- COMMAND [ARG...]"; }
SCOPE=""; TARGET=""; IMAGE=""
while (($#)); do
 case "$1" in
  --scope) SCOPE="${2:?missing scope}"; shift 2;;
  --target) TARGET="${2:?missing target}"; shift 2;;
  --image) IMAGE="${2:?missing image}"; shift 2;;
  --) shift; break;;
  -h|--help) usage; exit 0;;
  *) echo "Unknown option: $1" >&2; usage >&2; exit 2;;
 esac
done
[[ -n "$SCOPE" && -n "$TARGET" && -n "$IMAGE" && $# -gt 0 ]] || { usage >&2; exit 2; }
command -v docker >/dev/null || { echo "Docker required" >&2; exit 10; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 10; }
[[ -f "$SCOPE" && -d "$TARGET" ]] || { echo "Scope and target must exist" >&2; exit 2; }
docker info --format '{{json .Runtimes}}' | jq -e 'has("runsc")' >/dev/null || {
 echo "SECURITY BLOCK: gVisor runsc is unavailable; refusing weaker isolation." >&2; exit 11;
}
TARGET="$(cd "$TARGET" && pwd -P)"
SCOPE="$(cd "$(dirname "$SCOPE")" && pwd -P)/$(basename "$SCOPE")"
jq -e --arg target "$TARGET" --arg image "$IMAGE" '
 .authorized == true and .target_path == $target and
 .allowed_image == $image and (.expires_at | type == "string" and length > 0)
' "$SCOPE" >/dev/null || { echo "SECURITY BLOCK: scope mismatch or unauthorized." >&2; exit 12; }
EXPIRES="$(jq -r '.expires_at' "$SCOPE")"
if ! date -u -d "$EXPIRES" >/dev/null 2>&1 || [[ "$(date -u +%s)" -ge "$(date -u -d "$EXPIRES" +%s)" ]]; then
 echo "SECURITY BLOCK: scope expired or invalid." >&2; exit 12
fi
echo "Launching gVisor container: network disabled, target read-only, bounded resources."
exec docker run --rm --runtime=runsc --network=none --read-only \
 --cap-drop=ALL --security-opt=no-new-privileges:true --security-opt=seccomp=default \
 --pids-limit=128 --memory=512m --memory-swap=512m --cpus=1 \
 --ulimit nofile=256:256 --ulimit nproc=128:128 --user=65534:65534 \
 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
 --mount "type=bind,src=$TARGET,dst=/target,readonly" --workdir /target \
 --env ZEROFACTOR_TARGET=/target "$IMAGE" "$@"
