#!/usr/bin/env bash
# Read-only verification of the dedicated VM's outbound firewall policy.
set -euo pipefail
SCOPE="${1:-}"
[[ -n "$SCOPE" && -f "$SCOPE" ]] || { echo "Usage: verify-egress-policy.sh <live-scope.json>" >&2; exit 2; }
command -v nft >/dev/null || { echo "nftables is required" >&2; exit 10; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 10; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 10; }
jq -e '.live_network == true and (.allowed_destination_ips | type == "array" and length > 0)' "$SCOPE" >/dev/null || {
  echo "SECURITY BLOCK: scope must explicitly enable live_network and list destination IPs" >&2; exit 10;
}
CHAIN="$(nft list chain inet zerofactor_lab output 2>/dev/null)" || {
  echo "SECURITY BLOCK: inet zerofactor_lab output chain is absent" >&2; exit 11;
}
grep -Eq 'policy drop' <<<"$CHAIN" || { echo "SECURITY BLOCK: output chain must have policy drop" >&2; exit 13; }
grep -Fq 'oifname "lo" accept' <<<"$CHAIN" || { echo "SECURITY BLOCK: loopback exception missing" >&2; exit 14; }
grep -Fq 'ct state established,related accept' <<<"$CHAIN" || { echo "SECURITY BLOCK: established runner control channel exception missing" >&2; exit 15; }
grep -Fq 'ip daddr @approved_v4 tcp dport 443 accept' <<<"$CHAIN" || { echo "SECURITY BLOCK: IPv4 exact-IP HTTPS allow rule missing" >&2; exit 16; }
grep -Fq 'ip6 daddr @approved_v6 tcp dport 443 accept' <<<"$CHAIN" || { echo "SECURITY BLOCK: IPv6 exact-IP HTTPS allow rule missing" >&2; exit 17; }
ACCEPTS="$(grep -Ec ' accept$' <<<"$CHAIN" || true)"
[[ "$ACCEPTS" -eq 4 ]] || { echo "SECURITY BLOCK: unexpected accept rules (expected 4, found $ACCEPTS)" >&2; exit 18; }
V4="$(nft list set inet zerofactor_lab approved_v4 2>/dev/null)" || { echo "SECURITY BLOCK: approved_v4 set missing" >&2; exit 19; }
V6="$(nft list set inet zerofactor_lab approved_v6 2>/dev/null)" || { echo "SECURITY BLOCK: approved_v6 set missing" >&2; exit 19; }
for ip in $(jq -r '.allowed_destination_ips[]' "$SCOPE"); do
  if [[ "$ip" == *:* ]]; then
    grep -Fq "$ip" <<<"$V6" || { echo "SECURITY BLOCK: target IPv6 $ip is not in firewall set" >&2; exit 21; }
  else
    grep -Fq "$ip" <<<"$V4" || { echo "SECURITY BLOCK: target IPv4 $ip is not in firewall set" >&2; exit 21; }
  fi
done
if grep -Eq '0\.0\.0\.0/0|::/0|dport (53|80) accept|udp dport 53 accept|tcp dport 22 accept' <<<"$CHAIN$V4$V6"; then
  echo "SECURITY BLOCK: wildcard, DNS, HTTP or SSH egress rule detected" >&2; exit 20;
fi
python3 - "$V4" "$V6" <<'PY'
import ipaddress
import re
import sys

for family_text in sys.argv[1:]:
    candidates = re.findall(r'(?<![0-9A-Fa-f:.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?|(?<![0-9A-Fa-f:.])[0-9A-Fa-f:]{2,}(?:/[0-9]{1,3})?', family_text)
    for candidate in candidates:
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            continue
        if network.prefixlen == 0 or not network.is_global:
            raise SystemExit("SECURITY BLOCK: firewall set contains a wildcard or non-global destination range")
PY
echo "egress policy verified: default DROP; loopback + established + globally routable approved TCP/443 destinations"
echo "NOTE: also verify GitHub runner CIDRs and the cloud security-group/network ACL independently."
