#!/usr/bin/env bash
# Read-only verification of the dedicated VM's outbound firewall policy.
set -euo pipefail
command -v nft >/dev/null || { echo "nftables is required" >&2; exit 10; }
TABLE="$(nft list table inet zerofactor_lab 2>/dev/null)" || {
  echo "SECURITY BLOCK: inet zerofactor_lab table is absent" >&2; exit 11;
}
CHAIN="$(nft list chain inet zerofactor_lab output 2>/dev/null)" || {
  echo "SECURITY BLOCK: output chain is absent" >&2; exit 12;
}
grep -Eq 'policy drop' <<<"$CHAIN" || {
  echo "SECURITY BLOCK: output chain must have policy drop" >&2; exit 13;
}
grep -Fq 'oifname "lo" accept' <<<"$CHAIN" || {
  echo "SECURITY BLOCK: loopback exception missing" >&2; exit 14;
}
grep -Fq 'ct state established,related accept' <<<"$CHAIN" || {
  echo "SECURITY BLOCK: established runner control channel exception missing" >&2; exit 15;
}
grep -Fq 'ip daddr @approved_v4 tcp dport 443 accept' <<<"$CHAIN" || {
  echo "SECURITY BLOCK: IPv4 exact-IP HTTPS allow rule missing" >&2; exit 16;
}
grep -Fq 'ip6 daddr @approved_v6 tcp dport 443 accept' <<<"$CHAIN" || {
  echo "SECURITY BLOCK: IPv6 exact-IP HTTPS allow rule missing" >&2; exit 17;
}
ACCEPTS="$(grep -Ec ' accept$' <<<"$CHAIN" || true)"
[[ "$ACCEPTS" -eq 4 ]] || {
  echo "SECURITY BLOCK: output chain has unexpected accept rules (expected exactly 4, found $ACCEPTS)" >&2; exit 18;
}
V4="$(nft list set inet zerofactor_lab approved_v4 2>/dev/null)"
V6="$(nft list set inet zerofactor_lab approved_v6 2>/dev/null)"
grep -Eq 'elements[[:space:]]*=' <<<"$V4$V6" || {
  echo "SECURITY BLOCK: approved destination sets are empty or not populated" >&2; exit 19;
}
if grep -Eq 'dport (53|80) accept|udp dport 53 accept|tcp dport 22 accept' <<<"$CHAIN"; then
  echo "SECURITY BLOCK: DNS, HTTP or SSH egress must not be broadly allowed by this table" >&2; exit 20;
fi
echo "egress policy structure verified: default DROP; loopback + established + exact-IP TCP/443 only"
echo "NOTE: this verifier does not validate the correctness of the IP set contents or upstream cloud firewall."
