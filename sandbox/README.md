# Isolated execution laboratory

This is a guarded launcher, not a claim that a complete sandbox service is already operational.

Requirements:
- Linux host with Docker and gVisor runsc registered as a Docker runtime.
- A prebuilt, pinned, trusted test image. The launcher never pulls images.
- Disposable target and explicit written authorization.
- Dedicated host or VM for meaningful containment.

The launcher refuses to fall back to default Docker isolation. It disables network,
mounts the target read-only, uses a read-only root filesystem, drops capabilities,
enables no-new-privileges and seccomp, runs unprivileged, and enforces CPU, memory,
process and file-descriptor limits.

Copy scope.example.json and set authorized=true only after written authorization.
Bind the exact canonical target path, exact image reference and expiry. The example
is intentionally unauthorized.

Example:
  sandbox/run-isolated.sh --scope scope.json --target /srv/lab/project \
    --image local/zerofactor-runner:pinned -- ./run-approved-tests

Never mount production secrets, host sockets, Docker socket, SSH agents or writable
host directories. gVisor does not replace host patching, VM isolation or operational
controls. Validate isolation independently before production use.
