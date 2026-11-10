# Dedicated VM egress firewall

The live HTTPS adapter is not allowed to use DNS to choose a destination. The scope must contain literal `allowed_destination_ips`; the adapter connects directly to one of those IPs while preserving TLS hostname verification and SNI. Private, loopback, link-local, reserved and non-global addresses are rejected.

## Required boundary

- Run the active adapter directly on the dedicated disposable VM host, not inside the existing `--network=none` gVisor container.
- Keep `sandbox/run-isolated.sh` network-disabled for local fixture execution.
- Apply a VM-level/cloud security-group egress policy and a host nftables output policy.
- Permit only exact approved target IPs and the current, reviewed GitHub Actions runner control-plane CIDRs on TCP/443.
- Keep DNS, HTTP/80, arbitrary TCP/UDP, metadata endpoints, private ranges and all other egress blocked.
- Do not add broad accept rules for Docker bridges. Do not share this VM with production or ATIBON secrets.
- The GitHub runner's already-established control channel is retained; runner reconnection requires its currently approved IP ranges to be present in the sets.

## Prepare the firewall

1. Start with a clean disposable VM snapshot and out-of-band console access. The output policy intentionally defaults to DROP and can terminate remote management.
2. Review `zerofactor-lab.nft.example`; populate the two IP sets with the exact target addresses in the signed-off scope and current GitHub Actions runner CIDRs obtained from GitHub's official metadata.
3. Confirm the approved target IPs match `allowed_destination_ips` exactly. Never put DNS names, broad `0.0.0.0/0`, `::/0`, or private/metadata ranges in the target set.
4. Validate the rules before applying them: `sudo nft -c -f /path/to/reviewed-rules.nft`.
5. Apply only from the VM console: `sudo nft -f /path/to/reviewed-rules.nft`.
6. Run `sudo bash sandbox/verify-egress-policy.sh` from the checked-out repository. Then independently verify the cloud security group/network ACL.
7. Run the read-only adapter only after both firewall layers pass.

The example file is a template, not a production-ready policy. ZEROFACTOR does not install or alter host firewall rules automatically. The verifier checks rule structure but cannot certify the accuracy of the IP sets or a cloud firewall.

## Live adapter restrictions

- One sequential GET/HEAD request per allowlisted route, at most 12 requests total.
- HTTPS certificate verification, fixed port 443, no redirects, no proxy environment variables, no cookies, no credentials, no request body.
- Maximum 64 KiB response body per GET; response bodies are never persisted. Only status, selected metadata, byte count and SHA-256 digest are recorded.
- AUTH routes must be explicitly marked protected; FILE is HEAD-only.
- RATE is one passive observation and cannot establish absence of rate limiting.
- RECOVERY reads a health endpoint only; it never initiates a restore, restart or failover.
- INPUT remains fixture-only because active value submission would require write-capable requests.

Any failed response-policy comparison becomes a `needs_review` candidate, not an automatically confirmed vulnerability.
