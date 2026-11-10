# Dedicated VM egress policy

## Intended trust boundary

This policy is for a disposable ZEROFACTOR VM only. It is not a substitute for the cloud security group/network ACL. Enforce the same default-deny policy at the VM's network perimeter.

- No public inbound ports. Use the cloud provider's serial/console access for administration.
- Permit the runner host to reach only one fixed, approved HTTPS egress proxy IP and TCP port.
- Configure the ephemeral GitHub runner service with `HTTPS_PROXY` and `HTTP_PROXY` pointing to that proxy. The proxy itself enforces an FQDN allowlist for the minimum GitHub Actions endpoints required by the runner.
- Do not allow arbitrary DNS, direct internet egress, SSH agent forwarding, cloud metadata endpoints, or direct package/image downloads during a test job.
- Install updates and preload digest-pinned images before applying the locked-down runner policy; then snapshot the VM.
- The gVisor test containers use `--network=none`. The host proxy is for runner control-plane traffic only, not for controlled test containers.

## Apply the host nftables policy

From the VM console on the disposable host:

```bash
sudo ZF_EGRESS_PROXY_IP=192.0.2.10 ZF_EGRESS_PROXY_PORT=3128 bash sandbox/apply-vm-egress-policy.sh
```

Replace the documentation-only address with the real fixed proxy IPv4 address supplied by the VM/network operator. Do not guess or use a public proxy. The script installs a dedicated nftables table with default-drop input, output and forward chains. It permits loopback, established traffic and new outbound TCP only to the configured proxy. It deliberately permits no new inbound SSH connection.

Before enabling the runner service, configure its service environment with:

```
HTTPS_PROXY=http://192.0.2.10:3128
HTTP_PROXY=http://192.0.2.10:3128
NO_PROXY=localhost,127.0.0.1
```

Replace the example address. Verify that the runner can reach GitHub through the proxy and that direct outbound connections fail. Keep console access available for recovery. Do not apply this script to a workstation or production server.

## Validation evidence

Capture:
- Cloud security group/network ACL export showing default deny and proxy-only egress.
- `nft list ruleset` output and timestamp.
- Successful runner registration/one-job lifecycle through the proxy.
- Failed direct egress probes from the VM host.
- Confirmation that a gVisor test container has no network namespace route and cannot reach the proxy.
- VM image ID, kernel version, Docker version, runsc version, test image digest and GitHub workflow URL.

The fixture runner's `--network=none` is a second independent control. DNS/IP pinning for future live adapters is not implemented by this fixture-only runner. No live module adapter may be enabled until the VM egress controls and the dedicated gVisor host validation have passed review.
