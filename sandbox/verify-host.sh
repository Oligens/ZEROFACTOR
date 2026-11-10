#!/usr/bin/env bash
# Host-side gVisor smoke tests. This is not a sandbox-escape certification.
set -euo pipefail
command -v docker >/dev/null || { echo "Docker missing" >&2; exit 10; }
docker info --format '{{json .Runtimes}}' | grep -q '"runsc"' || { echo "gVisor runsc is not registered" >&2; exit 11; }
IMAGE="${ZEROFACTOR_TEST_IMAGE:-}"
[[ -n "$IMAGE" ]] || { echo "Set ZEROFACTOR_TEST_IMAGE to a preloaded, reviewed test image" >&2; exit 2; }
docker image inspect "$IMAGE" >/dev/null
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
echo "host-canary" > "$TMP/canary"
docker run --rm --runtime=runsc --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --pids-limit=32 --memory=128m --cpus=0.5 --user=65534:65534 --mount "type=bind,src=$TMP,dst=/probe,readonly" "$IMAGE" sh -c '
 test "$(cat /probe/canary)" = host-canary
 if touch /probe/should-not-write 2>/dev/null; then echo "read-only bind mount FAILED"; exit 21; fi
 if touch /should-not-write 2>/dev/null; then echo "read-only root FAILED"; exit 22; fi
 test ! -S /var/run/docker.sock
 echo "gVisor smoke checks passed"
'
echo "NOTE: selected controls only; this is not a kernel escape, side-channel, host-compromise or exhaustive resource-exhaustion test."
