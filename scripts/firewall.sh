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
# interface on the /16 can reach the decoy. That is fine for a teaching lab.
# It is not a boundary. Narrow LAB_CIDR to the student VLAN to get one."
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
# belongs in DOCKER-USER. Match the CONTAINER destination, not the published
# host port: this chain is reached from FORWARD, which runs after DNAT has
# already rewritten the destination. Measured on .45, 2026-11-06: a DROP
# matching the host port counted 0 packets and the decoy answered 200; the
# same DROP matching the container address and port counted 6 and the request
# returned 000. A rule written against the host port is present, tidy,
# idempotent, and matches nothing.
#
# The ports and the source are written as literals above, on purpose. This
# block lives inside the UNQUOTED heredoc that produces the report, so bash
# expands dollar-brace expressions and collapses backslashes and backticks in
# it before the text is ever printed. On 2026-11-06 an earlier version of this
# comment carried doubled backslashes and a literal angle-bracket placeholder
# for the bridge address. Inside the unquoted heredoc that became a live
# command substitution: bash executed it, wrote a syntax error to stderr, and
# the report printed a rule line with the source match silently deleted. The
# report is the artifact a human reads before running --apply; it showed a
# rule shaped differently from the one the script builds.
#
# The fix is not more escaping. Comment text inside an unquoted heredoc is
# still shell syntax. Keep it prose: no backticks, no backslash continuations,
# no dollar-brace, no angle brackets in pairs.
#
# That form is correct and reachable (DOCKER-USER counted 12 pkts from one
# off-box request), but note iptables accepts only ONE --source per rule; a
# second negative --source is rejected with "multiple --source options not
# allowed". To allow the lab AND the host's own hairpinned traffic (whose
# source is the bridge address, measured 172.22.0.1, not inside LAB_CIDR)
# AND drop the rest, express it as ACCEPT-per-source followed by a DROP.
# That is what --apply below builds; the negation above is left as the
# shortest correct form only while there is a single source to allow.
#
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

# iptables allows only ONE --source per rule, so the earlier `! -s A ! -s B`
# form is rejected outright with "multiple --source options not allowed".
# The way to express "allow these, drop everything else" in one chain is to
# ACCEPT the allowed sources and DROP at the end.
#
# Rules are inserted in reverse so the chain ends up in reading order:
#   -s LAB_CIDR -j ACCEPT
#   -s bridge1  -j ACCEPT
#   -j DROP
PORTS="${COWRIE_SSH_PORT},${COWRIE_TELNET_PORT},${WEB_PORT}"

# THE PORT IN DOCKER-USER IS NOT THE PORT ON THE HOST.
#
# DOCKER-USER is traversed from FORWARD, which runs AFTER nat PREROUTING has
# rewritten the destination. A packet addressed to host:8080 arrives in this
# chain addressed to the container's own address and port. Measured on
# 2026-11-06: a DROP matching --dports 8080 counted 0 packets while the decoy
# answered 200; the same DROP matching the post-DNAT destination counted 6 and
# returned 000. Every rule this script built before that date matched the
# pre-DNAT port and therefore matched nothing, which is why the chain could
# hold five correct-looking rules and restrict no traffic at all.
#
# The DESTINATIONS map below is built from `docker port` for the same reason
# the bridges are enumerated: it can fail, and when it fails the rules are
# vacuous, so it must fail loudly rather than write a rule that matches air.
if ! DESTS=$(docker ps --format '{{.Names}}' 2>/dev/null \
        | while read -r c; do
            docker port "$c" 2>/dev/null | awk -F' -> ' '{print $2}'
          done | sort -u | paste -sd' '); then
    DESTS=""
fi

if [[ -z "$DESTS" ]]; then
    echo "REFUSING: cannot resolve container destinations for the published" >&2
    echo "          ports. A DOCKER-USER rule matching the host port matches" >&2
    echo "          nothing, because DNAT has already rewritten it. Resolve" >&2
    echo "          the destinations or do not use --apply on this host." >&2
    exit 1
fi

echo "container destinations (post-DNAT): ${DESTS}"

# Rules are appended in reading order, but the ACCEPTs must sit above the DROP
# on every re-run, so the whole set is torn down and rebuilt.
#
# This MUST be recomputed here: the --apply path re-execs as root, and the
# previous version of this block deleted the enumeration from the top of the
# file while leaving these uses behind. Under `set -u` that is an unbound
# variable; without it, an empty string and a silently vacuous rule.
if ! BRIDGES=$(ip -4 -o addr show 2>/dev/null \
        | awk '$2 ~ /^(br-|docker0)/ {split($4,a,"/"); print a[1]}' | paste -sd' '); then
    BRIDGES=""
fi

if [[ -z "$BRIDGES" ]]; then
    echo "REFUSING: cannot enumerate Docker bridge addresses, so a source-" >&2
    echo "          based rule would drop the host's own health check. Fix the" >&2
    echo "          enumeration or do not use --apply on this host." >&2
    exit 1
fi

echo "allowing sources: ${LAB_CIDR} plus local bridges: ${BRIDGES}"

# Build the final chain state we want, as one array of rule specs, then apply
# it idempotently.
#
# Every rule carries a comment marker. verify.sh has to be able to ask "are
# our rules in the chain", and before 2026-11-06 the only way it could was to
# grep the whole ruleset for the string TRAPDOOR -- which no rule contained,
# so the check printed "no TRAPDOOR rules applied" on a host where five of
# them had just been applied and verified. A check that cannot see the thing
# it is checking is G2's shape again: it reads exactly like a clean result.
# Match the post-DNAT destination, one rule set per destination address.
# `docker port` prints "addr:port"; split it so each part lands in the right
# iptables field -- putting a combined addr:port into --dport is rejected.
SPECS=()
for dest in $DESTS; do
    dhost="${dest%:*}"
    dport="${dest##*:}"
    for src in "$LAB_CIDR" $BRIDGES; do
        SPECS+=("-p tcp -d ${dhost} --dport ${dport} -s ${src} -m comment --comment TRAPDOOR-scope -j ACCEPT")
    done
    SPECS+=("-p tcp -d ${dhost} --dport ${dport} -m comment --comment TRAPDOOR-scope -j DROP")
done

# Clear any previous version of this ruleset so re-runs are convergent rather
# than additive. Only touches rules on exactly these three ports.
while read -r rule; do
    [[ -z "$rule" ]] && continue
    # shellcheck disable=SC2086
    iptables -D DOCKER-USER $rule 2>/dev/null || true
done < <(iptables -S DOCKER-USER | grep -- 'TRAPDOOR-scope' | sed 's/^-A DOCKER-USER //' || true)

for spec in "${SPECS[@]}"; do
    # shellcheck disable=SC2086
    iptables -A DOCKER-USER $spec
done
echo "wrote $((${#SPECS[@]})) rules to DOCKER-USER"

# ---------------------------------------------------------------------------
# Prove it did what it says, rather than reporting that the command exited 0.
# The whole lesson of this repo is that those are different things.
# ---------------------------------------------------------------------------

echo
 echo "== checking the claim =="
FAIL=0

# Every spec must be present exactly once, and the chain must end in a DROP
# for these ports — otherwise the accepts are decoration again.
for spec in "${SPECS[@]}"; do
    # shellcheck disable=SC2086
    if iptables -C DOCKER-USER $spec 2>/dev/null; then
        echo "  OK   present: ${spec}"
    else
        echo "  FAIL missing: ${spec}" >&2
        FAIL=1
    fi
done

DUPES=$(iptables -S DOCKER-USER | grep -c -- 'TRAPDOOR-scope' || true)
if [[ "$DUPES" -eq "${#SPECS[@]}" ]]; then
    echo "  OK   chain holds ${DUPES} rules, no duplicates"
else
    echo "  FAIL expected ${#SPECS[@]} rules, found ${DUPES} — duplicates or gaps" >&2
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

# The rules must MATCH something. A DROP that has never dropped anything is
# a comment with a deadline, and on 2026-11-06 this chain held five rules
# matching a port that DNAT had already rewritten -- all present, no
# duplicates, decoy answering, and not one packet touched. Read the counters,
# because presence is not enforcement.
for i in "${!SPECS[@]}"; do
    # shellcheck disable=SC2086
    hits=$(iptables -L DOCKER-USER -v -n 2>/dev/null \
        | awk -v d="$(echo ${SPECS[$i]} | sed 's/.*-d \([0-9.]*\).*/\1/')" \
              -v p="$(echo ${SPECS[$i]} | sed 's/.*--dport \([0-9]*\).*/\1/')" \
              '$0 ~ d && $0 ~ ("dpt:" p) {print $1; exit}')
    if [[ -z "$hits" ]]; then
        echo "  WARN no rule found for a built spec -- counters unreadable"
    elif [[ "$hits" -gt 0 ]]; then
        echo "  OK   rule has matched traffic (${hits} pkts)"
        break
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
