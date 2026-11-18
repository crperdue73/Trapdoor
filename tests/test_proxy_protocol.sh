#!/bin/bash
# tests/test_proxy_protocol.sh - the two halves of source-address forwarding
# must always agree.
#
# Why this exists (2026-11-12):
#
# The decoy nginx holds :2222 and :2223 on the host and forwards inward to
# cowrie. Until today it forwarded WITHOUT telling cowrie who was calling, so
# cowrie logged the proxy's own address (172.23.0.4) for every attacker on
# earth. The console faithfully reported that. Six thousand events, one source.
#
# The fix is a matched pair:
#
#   web/nginx/nginx.conf   proxy_protocol on      (send the header)
#   cowrie/etc/cowrie.cfg  haproxy:tcp:...        (expect the header)
#
# Either one alone is worse than neither:
#
#   header sent, nobody reading  -> harmless, but the IP is still wrong
#   header expected, nobody sent -> cowrie waits for a PROXY line that never
#                                   arrives and EVERY connection hangs until
#                                   it times out. The honeypot goes dark and
#                                   looks like a network problem.
#
# That second failure is silent, total, and would be blamed on the firewall. So
# the two settings are checked together, and a half-edit fails the build.
#
# What it does NOT prove: that nginx actually emits a correct header, or that
# cowrie records the right address. Only a live connection proves that. This
# catches the half-applied edit, which is the realistic mistake.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

NGINX=web/nginx/nginx.conf
CFG=cowrie/etc/cowrie.cfg
FAIL=0
ok()   { echo "  OK    $*"; }
bad()  { echo "  FAIL  $*"; FAIL=1; }

for f in "$NGINX" "$CFG"; do
    if [[ ! -f $f ]]; then
        bad "$f is missing - cannot check the proxy protocol pair"
        echo
        echo "TESTS FAILED"
        exit 1
    fi
done

# Count the stream-server proxy_protocol directives. There are two listeners
# (:2222 ssh, :2223 telnet) and both need it, so the expected count is 2.
sends=$(grep -c '^[[:space:]]*proxy_protocol[[:space:]]\+on[[:space:]]*;' "$NGINX" || true)
expects=$(grep -c '^[[:space:]]*listen_endpoints[[:space:]]*=[[:space:]]*haproxy:' "$CFG" || true)

echo "nginx proxy_protocol on   : $sends (expected 2)"
echo "cowrie haproxy: endpoints : $expects (expected 2)"

if [[ $sends -eq 2 ]]; then
    ok "nginx sends the PROXY header on both stream listeners"
else
    bad "nginx has $sends proxy_protocol directives, expected 2 (:2222 and :2223)"
fi

if [[ $expects -eq 2 ]]; then
    ok "cowrie expects the PROXY header on both endpoints"
else
    bad "cowrie has $expects haproxy: endpoints, expected 2 (ssh and telnet)"
fi

# The pair must agree. Any mismatch is the dangerous state, in either
# direction, and the message must say which direction it is.
if [[ $sends -gt 0 && $expects -eq 0 ]]; then
    bad "HALF-APPLIED: nginx sends a PROXY header but cowrie does not expect"
    bad "  -> connections still log the proxy address. Add haproxy: prefixes."
elif [[ $sends -eq 0 && $expects -gt 0 ]]; then
    bad "HALF-APPLIED: cowrie expects a PROXY header but nginx does not send one"
    bad "  -> EVERY connection will hang until timeout. Add proxy_protocol on;"
elif [[ $sends -gt 0 && $expects -gt 0 ]]; then
    ok "both halves are configured together"
fi

# The shipper reads cowrie's JSON. If the field it reads is not src_ip, the
# console would show something else entirely and this whole fix lands nowhere.
if grep -q 'src_ip' shipper/shipper.py 2>/dev/null; then
    ok "shipper reads src_ip from cowrie events"
else
    bad "shipper/shipper.py does not mention src_ip - the fix may not reach the console"
fi

echo
if [[ $FAIL -ne 0 ]]; then
    echo "TESTS FAILED"
    exit 1
fi
echo "passed"
