#!/usr/bin/env bash
# Apply a fail-closed egress policy to a disposable ZEROFACTOR VM.
# Requires nftables, a static IPv4 HTTPS egress proxy and console access for recovery.
set -euo pipefail
: "${ZF_EGRESS_PROXY_IP:?Set ZF_EGRESS_PROXY_IP to the fixed IPv4 address of the approved HTTPS egress proxy}"
PROXY_PORT="${ZF_EGRESS_PROXY_PORT:-3128}"
if [[ ! "$ZF_EGRESS_PROXY_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "SECURITY BLOCK: ZF_EGRESS_PROXY_IP must be an IPv4 address" >&2; exit 2
fi
if [[ ! "$PROXY_PORT" =~ ^[0-9]{1,5}$ ]] || (( PROXY_PORT < 1 || PROXY_PORT > 65535 )); then
  echo "SECURITY BLOCK: invalid ZF_EGRESS_PROXY_PORT" >&2; exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then echo "Run as root on the disposable VM" >&2; exit 2; fi
command -v nft >/dev/null || { echo "nftables is required" >&2; exit 2; }
echo "WARNING: installs default-drop input/output policy in the dedicated inet zerofactor table."
echo "Allows outbound TCP only to the approved proxy and blocks new inbound connections."
echo "Use VM console access; do not run on a workstation or production host."
nft delete table inet zerofactor 2>/dev/null || true
nft -f - <<NFT
table inet zerofactor {
  chain input {
    type filter hook input priority -100; policy drop;
    iifname "lo" accept
    ct state established,related accept
  }
  chain output {
    type filter hook output priority -100; policy drop;
    oifname "lo" accept
    ct state established,related accept
    ip daddr $ZF_EGRESS_PROXY_IP tcp dport $PROXY_PORT ct state new accept
  }
  chain forward {
    type filter hook forward priority -100; policy drop;
  }
}
NFT
nft list table inet zerofactor
echo "Egress restricted. Configure the ephemeral runner service with HTTPS_PROXY=http://$ZF_EGRESS_PROXY_IP:$PROXY_PORT."
