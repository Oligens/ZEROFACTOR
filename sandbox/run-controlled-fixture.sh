#!/usr/bin/env bash
# Run one offline controlled-module fixture inside gVisor with networking disabled.
set -euo pipefail
MODULE="${1:-}"; SCOPE="${2:-}"; FIXTURE="${3:-}"; OUTPUT_DIR="${4:-}"
[[ "$MODULE" =~ ^(AUTH|INPUT|FILE|RATE|RECOVERY)$ ]] || { echo "Usage: $0 MODULE SCOPE.json FIXTURE.json OUTPUT_DIR" >&2; exit 2; }
[[ -f "$SCOPE" && ! -L "$SCOPE" && -f "$FIXTURE" && ! -L "$FIXTURE" ]] || { echo "Scope and fixture must be regular, non-symlink files" >&2; exit 2; }
[[ -n "$OUTPUT_DIR" ]] || { echo "Output directory is required" >&2; exit 2; }
command -v docker >/dev/null
command -v jq >/dev/null
command -v timeout >/dev/null
docker info --format '{{json .Runtimes}}' | grep -q '"runsc"' || { echo "SECURITY BLOCK: gVisor runsc unavailable" >&2; exit 11; }
IMAGE="${ZEROFACTOR_MODULE_IMAGE:-}"
[[ "$IMAGE" =~ @sha256:[a-f0-9]{64}$ ]] || { echo "SECURITY BLOCK: ZEROFACTOR_MODULE_IMAGE must be pinned by sha256 digest" >&2; exit 12; }
docker image inspect "$IMAGE" >/dev/null
mkdir -p "$OUTPUT_DIR"
SCOPE_ABS="$(cd "$(dirname "$SCOPE")" && pwd -P)/$(basename "$SCOPE")"
FIXTURE_ABS="$(cd "$(dirname "$FIXTURE")" && pwd -P)/$(basename "$FIXTURE")"
OUT_ABS="$(cd "$OUTPUT_DIR" && pwd -P)"
FIXTURE_ID="$(jq -er '.case_id | strings' "$FIXTURE_ABS")"
jq -e --arg module "$MODULE" --arg fixture "$FIXTURE_ID" '
  .authorized == true and (.modules | index($module) != null) and
  (.fixture_ids | type == "array" and index($fixture) != null)
' "$SCOPE_ABS" >/dev/null || { echo "SECURITY BLOCK: module or fixture ID not explicitly authorized" >&2; exit 13; }
python3 "$(dirname "$0")/../scripts/validate_scope.py" --scope "$SCOPE_ABS" >/dev/null
timeout --signal=TERM --kill-after=5s 40s docker run --rm --pull=never --runtime=runsc --network=none --read-only \
  --cap-drop=ALL --security-opt=no-new-privileges:true --security-opt=seccomp=default \
  --pids-limit=64 --memory=256m --memory-swap=256m --cpus=0.5 \
  --ulimit nofile=128:128 --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --mount "type=bind,src=$(cd "$(dirname "$0")/.." && pwd -P)/scripts,dst=/opt/zerofactor/scripts,readonly" \
  --mount "type=bind,src=$FIXTURE_ABS,dst=/fixture.json,readonly" \
  --mount "type=bind,src=$SCOPE_ABS,dst=/scope.json,readonly" \
  --mount "type=bind,src=$OUT_ABS,dst=/out" \
  --env PYTHONDONTWRITEBYTECODE=1 \
  "$IMAGE" python3 /opt/zerofactor/scripts/controlled_modules.py \
  --module "$MODULE" --scope /scope.json --fixture /fixture.json \
  --output "/out/$MODULE-result.json"
RESULT="$OUT_ABS/$MODULE-result.json"
test -s "$RESULT"
test "$(wc -c < "$RESULT")" -le 262144
jq -e '.evidence_kind == "synthetic_fixture" and .safety.network_connections == 0 and .safety.target_files_read == 0 and .safety.target_files_written == 0 and .safety.credentials_used == 0' "$RESULT" >/dev/null
echo "Offline $MODULE fixture evaluation completed; output=$RESULT"
