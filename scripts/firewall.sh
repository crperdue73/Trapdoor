#!/usr/bin/env bash
# TRAPDOOR firewall rules.
#
# Prints by default. `--apply` writes them. A honeypot that silently rewrites
# the host firewall on first start is a surprise nobody wants at 2am, so the
# default is print-only and a human reads it first.
#
# Threat model this addresses:
#   - someone outside LAB_CIDR reaching the decoy (should be nobody)
#   - the honeypot being used as a pivot outward (already blocked at the
#     Docker network layer with internal: true, this is belt and braces)

set -euo pipefail

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

# shellcheck disable=SC1091
[[ -f .env ]] && source .env

LAB_CIDR="${LAB_CIDR:-192.168.0.0/16}"
LAB_BIND_IP="${LAB_BIND_IP:-192.168.111.45}"
COWRIE_SSH_PORT="${COWRIE_SSH_PORT:-2222}"
COWRIE_TELNET_PORT="${COWRIE_TELNET_PORT:-2223}"
WEB_PORT="${WEB_PORT:-8080}"

if [[ "$LAB_CIDR" == "0.0.0.0/0" ]]; then
    echo "REFUSING: LAB_CIDR is 0.0.0.0/0. This is an internal lab; the whole" >&2
    echo "          internet does not get to reach it. Set LAB_CIDR in .env." >&2
    exit 1
fi

read -r -d '' RULES <<EOF || true
# TRAPDOOR — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Lab subnet: ${LAB_CIDR}

# 1. Allow the lab subnet to reach the decoy ports.
iptables -A INPUT -p tcp -s ${LAB_CIDR} --dport ${COWRIE_SSH_PORT}   -j ACCEPT
iptables -A INPUT -p tcp -s ${LAB_CIDR} --dport ${COWRIE_TELNET_PORT} -j ACCEPT
iptables -A INPUT -p tcp -s ${LAB_CIDR} --dport ${WEB_PORT}         -j ACCEPT

# 2. Drop the same ports from everywhere else. Default-deny, stated
#    explicitly rather than relying on a policy that changes elsewhere.
iptables -A INPUT -p tcp --dport ${COWRIE_SSH_PORT}   -j DROP
iptables -A INPUT -p tcp --dport ${COWRIE_TELNET_PORT} -j DROP
iptables -A INPUT -p tcp --dport ${WEB_PORT}          -j DROP

# 3. What LAB_CIDR=192.168.0.0/16 means, stated plainly because it is easy to
#    misread as an allowlist.
#
#    It is the whole farm. Every agent host, every LXC, every management
#    interface, the PVE nodes, the printers, whatever else lives on the /16.
#    So "allow the lab subnet to reach the decoy ports" means: every machine
#    on the network can reach 2222, 2223 and 8080 on this box. That is the
#    intended teaching model — students scan it, and so can anything else here.
#
#    Rule 1 exists to bound the blast radius of the decoy, not to make the
#    decoy private. The DMZ is one-way by design and does not exist here.
#
#    It is also nearly a no-op in practice. Rule 2 DROPs the same ports from
#    everywhere else, and "everywhere else" on a flat /16 with on-link routing
#    resolves to almost nothing. The rules that actually hold the line are:
#
#      - LAB_BIND_IP binding the published ports to one address (not 0.0.0.0)
#      - internal: true on the honeynet, so the decoy has no route out
#
#    Both are verified by scripts/verify.sh. This script is the third opinion.
#
#    If a narrower boundary is ever wanted, the change is LAB_CIDR to the
#    student VLAN only — a one-line change with a visible diff, which is the
#    right shape for a security control.

# 4. Deliberately NOT dropping FORWARD from LAB_BIND_IP.
#
#    An earlier draft had \`iptables -A FORWARD -s \${LAB_BIND_IP} -j DROP\` as
#    a belt-and-braces backstop. Vera flagged it and she is right: Docker's
#    bridge traffic is FORWARDed, so a source-scoped DROP there can cut the
#    FORWARD path the lab itself may need later — and it would fail in a way
#    that looks like "Docker is broken" rather than "a firewall rule did it."
#
#    The real egress control is \`internal: true\` on the honeynet bridge, which
#    gives the honeypot containers no route at all. That is a stronger control
#    than this rule would have been. If a container ever moves off that
#    network, add the FORWARD DROP *then*, deliberately, as its own change.
#
#    Kept as a comment because the next person will wonder why it is missing.
EOF

if $APPLY; then
    # Save first: a firewall change with no rollback path is a way to lock
    # yourself out of a box you needed to fix.
    STAMP=$(date -u +%Y%m%dT%H%M%SZ)
    iptables-save > "/root/iptables-backup-${STAMP}.rules" 2>/dev/null || true
    echo "$RULES" | grep -v '^#' | grep -v '^$' | while read -r line; do
        $line
    done
    echo "applied. rollback file: /root/iptables-backup-${STAMP}.rules"
else
    echo "$RULES"
    echo
    echo "# --- printed only. re-run with --apply to install, after reading it. ---"
fi
