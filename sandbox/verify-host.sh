#!/usr/bin/env bash
# Host-side gVisor smoke tests. This is not a sandbox-escape certification.
set -euo pipefail
command -v docker >/dev/null || { echo "Docker missing" >&2; exit 10; }
docker info --format '{{json .Runtimes}}' | grep -q '"runsc"' || { echo "gVisor runsc is not registered" >&2; exit 11; }
IMAGE="${ZEROFACTOR_TEST_IMAGE:-}"
[[ -n "$IMAGE" ]] || { echo "Set ZEROFACTOR_TEST_IMAGE to a preloaded, reviewed test image" >&2; exit 2; }
docker image inspect "$IMAGE" >/dev/null
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "host-canary" > "$TMP/canary"
docker run --rm --runtime=runsc --network=none --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges:true --security-opt=seccomp=default \
  --pids-limit=32 --memory=128m --memory-swap=128m --cpus=0.5 \
  --ulimit nofile=128:128 --user=65534:65534 \
  --mount "type=bind,src=$TMP,dst=/probe,readonly" "$IMAGE" sh -c '
    set -eu
    test "$(cat /probe/canary)" = host-canary
    if touch /probe/should-not-write 2>/dev/null; then echo "read-only bind mount FAILED"; exit 21; fi
    if touch /should-not-write 2>/dev/null; then echo "read-only root FAILED"; exit 22; fi
    test ! -e /var/run/docker.sock
    uid="$(awk "/^Uid:/ {print \$2}" /proc/self/status)"
    test "$uid" = "65534" || { echo "unprivileged UID check FAILED: $uid"; exit 23; }
    caps="$(awk "/^CapEff:/ {print \$2}" /proc/self/status)"
    test "$caps" = "0000000000000000" || { echo "capability drop FAILED: $caps"; exit 24; }
    seccomp="$(awk "/^Seccomp:/ {print \$2}" /proc/self/status)"
    test "$seccomp" = "2" || { echo "seccomp check FAILED: $seccomp"; exit 25; }
    if awk "NR>1 && \$2 == \"00000000\" {found=1} END {exit !found}" /proc/net/route; then
      echo "network isolation FAILED: default route exists"; exit 26
    fi
    echo "gVisor confinement smoke checks passed"
  '
echo "NOTE: selected controls only; this is not a kernel escape, side-channel, host-compromise or exhaustive resource-exhaustion test."
