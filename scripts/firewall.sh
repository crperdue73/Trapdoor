#!/usr/bin/env bash
# TRAPDOOR firewall rules.
#
# Prints by default. `--apply` writes them. A honeypot that silently rewrites
# the host firewall on first start is a surprise nobody wants at 2am, so the
# default is print-only and a human reads it first.
#
# ---------------------------------------------------------------------------
# WHAT ACTUALLY HAPPENS TO A PACKET (measured on .45, 2026-11-02)
#
# I got this wrong twice in one afternoon, in opposite directions, so it is
# written down here rather than rediscovered a third time.
#
# Off-box request to http://192.168.111.45:8080, sent from 192.168.111.43:
#
#   nat PREROUTING -> DOCKER chain -> DNAT to the container
#   FORWARD -> DOCKER-USER  <-- visible here (counted 12 pkts / 2230 bytes)
#   INPUT: never touched
#
# So:
#   - DOCKER-USER rules DO see off-box traffic. That is the one usable hook.
#   - INPUT rules do not, for DNATed traffic. An INPUT DROP on 8080 blocks
#     only loopback (measured: .45 -> 200 but 127.0.0.1 -> 000).
#   - ufw's INPUT chain therefore does not protect the decoy at all.
#
# With LAB_CIDR=192.168.0.0/16 the DOCKER-USER rule `! -s 192.168.0.0/16`
# matches nothing, because every host on this farm is inside /16. The rule is
# present, reachable, correct, and does nothing. That is not a bug in the
# rule; it is the rule faithfully implementing a scope that was set too wide.
#
# Consequence worth stating plainly: on this box the decoy is open to the
# whole /16, and the only reason it is not open to the internet is that the
# farm is triple-NATed. Not because of the firewall.
# ---------------------------------------------------------------------------
#
# The previous version emitted six rules, all of which failed to do what the
# file implied (2026-11-02):
#
#   iptables -A INPUT -p tcp -s $LAB_CIDR --dport 2222 -j ACCEPT
#   iptables -A INPUT -p tcp -s $LAB_CIDR --dport 2223 -j ACCEPT
#   iptables -A INPUT -p tcp -s $LAB_CIDR --dport 8080 -j ACCEPT
#   iptables -A INPUT -p tcp --dport 2222 -j DROP
#   iptables -A INPUT -p tcp --dport 2223 -j DROP
#   iptables -A INPUT -p tcp --dport 8080 -j DROP
#
# Every one of those six was wrong on the live host, in two different ways.
#
# 1. THE DROPS BLOCKED THE WRONG THING.
#    The decoy ports are published by Docker, so the listener is docker-proxy
#    bound to 192.168.111.45. Traffic to it arrives on INPUT, but it arrives
#    from the host's own routing, not from the lab subnet's source address as
#    far as the rule is concerned. Measured on .45:
#
#      with `-I INPUT -p tcp --dport 8080 -j DROP` at the top of the chain:
#        http://192.168.111.45:8080  -> 200   (decoy still serving the lab)
#        http://127.0.0.1:8080       -> 000   (blocked)
#        http://localhost:8080       -> 000   (blocked)
#
#    So the rule did not close the door to students. It closed it to the
#    health check, which curls the bound address and would have started
#    failing verify for a reason nobody could see in the firewall.
#
#    Correction to an earlier note in this header: the caveat about rules not
#    seeing INPUT applies where DNAT bypasses INPUT entirely, and off-box
#    traffic is DNATed. So the INPUT DROPs were wrong for two reasons, not
#    one: unreachable for the lab, and harmful to loopback.
#
# 2. THE ACCEPTS NEVER FIRED AT ALL.
#    ufw is active on this host and its chain is jumped from INPUT ahead of
#    anything appended later. Appending an ACCEPT after `-j ufw-before-input`
#    puts it below ufw's default-deny, where it is unreachable. The allow
#    rules were decorative. `iptables -A` on this box is the wrong verb.
#
# The deeper problem is that this script was writing rules to a chain that
# Docker and ufw already own, and claiming a boundary that was being drawn
# somewhere else entirely. The boundary that actually exists:
#
#   - LAB_BIND_IP binds the published ports to one address, not 0.0.0.0
#   - internal: true on the honeynet gives the decoy no route outward
#   - ufw denies inbound except SSH
#
# Both of the first two are verified by scripts/verify.sh, by measurement, on
# every run. So this script no longer invents a parallel implementation. It
# states the boundary, emits the one rule shape that is both correct and
# reachable if someone asks for it, and refuses to pretend the rest exists.
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# The honest report. This is the part that has value; the rules below are
# secondary, and on most deployments should never be applied.
# ---------------------------------------------------------------------------

if [[ "$LAB_CIDR" == "192.168.0.0/16" ]]; then
    CIDR_NOTE="the WHOLE FARM. Every LXC, every agent host, every management
#    interface on the /16 can reach the decoy. That is fine for a teaching lab.
#    It is not a boundary. Narrow LAB_CIDR to the student VLAN to get one."
else
    CIDR_NOTE="${LAB_CIDR}"
fi

cat <<EOF
# TRAPDOOR — firewall state as of $(date -u +%Y-%m-%dT%H:%M:%SZ)
#
# BOUNDARY THAT ACTUALLY EXISTS (each measured by scripts/verify.sh):
#   1. published ports bound to ${LAB_BIND_IP}, never 0.0.0.0
#   2. honeynet is internal: true — the decoy has no route out
#   3. ufw default-deny inbound, except SSH
#
# LAB_CIDR = ${CIDR_NOTE}
#
# This script does NOT add INPUT rules to close the decoy ports, because on
# this host INPUT never sees them: published ports are DNATed, and off-box
# traffic goes nat PREROUTING -> DOCKER -> FORWARD/DOCKER-USER. An INPUT DROP
# on 8080 reaches only loopback — measured on .45: 192.168.111.45 -> 200 while
# 127.0.0.1 -> 000 — so it breaks the health check and closes nothing.
#
# IF YOU GENUINELY NEED TO RESTRICT THE DECOY AT THE FIREWALL LAYER, the rule
# belongs in DOCKER-USER, which Docker evaluates before its own FORWARD rules
# and which nothing else here appends to:
#
#   iptables -I DOCKER-USER -p tcp -m multiport \\
#       --dports ${COWRIE_SSH_PORT},${COWRIE_TELNET_PORT},${WEB_PORT} \\
#       ! -s ${LAB_CIDR} -j DROP
#
# That form is correct and reachable (DOCKER-USER counted 12 pkts from one
# off-box request). It is not applied by default for one honest reason: with
# LAB_CIDR at /16 the negated source match matches nothing, so it would sit
# in the chain
# looking like a control while allowing every host on the farm. A near-vacuous
# rule that looks like a boundary is worse than no rule, because it stops
# anyone from asking the question.
#
# Set LAB_CIDR to the student VLAN first, then re-run: the same rule becomes
# a real boundary with no other change.
EOF

if ! $APPLY; then
    echo
    echo "# --- printed only. nothing changed. ---"
    exit 0
fi

# ---------------------------------------------------------------------------
# --apply: make the DOCKER-USER rule explicit, idempotently, and prove it.
# ---------------------------------------------------------------------------

echo
echo "== applying =="

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP="/root/iptables-backup-${STAMP}.rules"
iptables-save > "$BACKUP"
echo "rollback file: ${BACKUP}"

# The rule has to allow the host itself, not just LAB_CIDR.
#
# Traffic from this host to its own published ports is hairpinned through
# POSTROUTING, so its source is rewritten to the bridge address (measured:
# 172.22.0.1) — which is NOT inside 192.168.0.0/16. A rule written as
# `! -s $LAB_CIDR -j DROP` therefore drops the host's own health check and
# the verify banner probe. That is exactly what happened on .45: verify went
# from green to "no SSH banner on port 2222", and removing this rule restored
# it instantly.
#
# So the rule accepts the lab AND every local Docker bridge, then drops.
BRIDGES=$(ip -4 -o addr show 2>/dev/null | awk '$2 ~ /^(br-|docker0)/ {split($4,a,"/"); print a[1]}' | paste -sd' ')

SOURCE_MATCH=(! -s "$LAB_CIDR")
for b in $BRIDGES; do
    SOURCE_MATCH+=(! -s "$b")
done

if [[ -z "$BRIDGES" ]]; then
    echo "REFUSING: cannot enumerate Docker bridge addresses, so a source-" >&2
    echo "          based rule would drop the host's own health check. Fix the" >&2
    echo "          enumeration or do not use --apply on this host." >&2
    exit 1
fi

echo "allowing sources: ${LAB_CIDR} plus local bridges: ${BRIDGES}"

RULE_ARGS=(-p tcp -m multiport --dports "${COWRIE_SSH_PORT},${COWRIE_TELNET_PORT},${WEB_PORT}" "${SOURCE_MATCH[@]}" -j DROP)

# Refuse to stack duplicates. `iptables -I` on every run is how a chain grows
# to two hundred identical lines over a year and nobody notices until a
# change takes ten minutes to locate.
if iptables -C DOCKER-USER "${RULE_ARGS[@]}" 2>/dev/null; then
    echo "rule already present, not adding a duplicate"
else
    iptables -I DOCKER-USER "${RULE_ARGS[@]}"
    echo "inserted into DOCKER-USER"
fi

# ---------------------------------------------------------------------------
# Prove it did what it says, rather than reporting that the command exited 0.
# The whole lesson of this repo is that those are different things.
# ---------------------------------------------------------------------------

echo
echo "== checking the claim =="
FAIL=0

if iptables -C DOCKER-USER "${RULE_ARGS[@]}" 2>/dev/null; then
    echo "  OK   DOCKER-USER rule is present"
else
    echo "  FAIL DOCKER-USER rule is NOT present after apply" >&2
    FAIL=1
fi

# The decoy must still answer the lab, or the rule is too wide.
for p in "$WEB_PORT"; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://${LAB_BIND_IP}:${p}/" || true)
    if [[ "$code" == "200" ]]; then
        echo "  OK   decoy still serving the lab on ${p} (${code})"
    else
        echo "  FAIL decoy stopped answering on ${p} after apply (got '${code}')" >&2
        echo "       roll back: iptables-restore < ${BACKUP}" >&2
        FAIL=1
    fi
done

# And it must still answer the health check, which reaches it the same way.
if curl -s -o /dev/null --max-time 5 "http://${LAB_BIND_IP}:${WEB_PORT}/"; then
    echo "  OK   health-check path intact"
else
    echo "  FAIL health-check path broke — this is the exact failure the old" >&2
    echo "       INPUT DROP caused. roll back: iptables-restore < ${BACKUP}" >&2
    FAIL=1
fi

# The decoy must still speak SSH to the host. This is the check that would
# have caught the rule above: an earlier version passed the HTTP probe and
# the health path, then quietly dropped every SSH packet from this host, and
# verify went from green to "no SSH banner on port 2222".
banner=$(timeout 5 nc "${LAB_BIND_IP}" "$COWRIE_SSH_PORT" </dev/null 2>/dev/null | head -1 || true)
if [[ "$banner" == SSH-2.0-* ]]; then
    echo "  OK   SSH banner still served from this host"
else
    echo "  FAIL SSH banner gone after apply (got '${banner}') — the rule is" >&2
    echo "       dropping the host's own traffic. roll back: iptables-restore < ${BACKUP}" >&2
    FAIL=1
fi

if [[ "$FAIL" -ne 0 ]]; then
    echo
    echo "apply did not verify. roll back with: iptables-restore < ${BACKUP}" >&2
    exit 1
fi

echo
echo "applied and verified."
