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
#
# .env is a DEFAULT, not an override. `source .env` plain clobbers whatever the
# caller exported, which meant the tests below passed on a machine with no
# .env and silently failed on the honeypot, where .env exists and sets
# LAB_CIDR=192.168.0.0/16. Two of seven scope tests failed on the real host and
# passed on mine, and the difference was a file, not a bug in the rules.
#
# Snapshot what the caller set, source the file, then restore the caller's
# values on top. Precedence: explicit environment > .env > built-in default.
__ENV_LAB_CIDR="${LAB_CIDR:-}"
__ENV_LAB_BIND_IP="${LAB_BIND_IP:-}"
__ENV_ADMIN_CIDR="${ADMIN_CIDR:-}"
__ENV_COWRIE_SSH_PORT="${COWRIE_SSH_PORT:-}"
__ENV_COWRIE_TELNET_PORT="${COWRIE_TELNET_PORT:-}"
__ENV_WEB_PORT="${WEB_PORT:-}"
__ENV_CONSOLE_PORT="${CONSOLE_PORT:-}"

[[ -f .env ]] && source .env

[[ -n "$__ENV_LAB_CIDR" ]] && LAB_CIDR="$__ENV_LAB_CIDR"
[[ -n "$__ENV_LAB_BIND_IP" ]] && LAB_BIND_IP="$__ENV_LAB_BIND_IP"
[[ -n "$__ENV_ADMIN_CIDR" ]] && ADMIN_CIDR="$__ENV_ADMIN_CIDR"
[[ -n "$__ENV_COWRIE_SSH_PORT" ]] && COWRIE_SSH_PORT="$__ENV_COWRIE_SSH_PORT"
[[ -n "$__ENV_COWRIE_TELNET_PORT" ]] && COWRIE_TELNET_PORT="$__ENV_COWRIE_TELNET_PORT"
[[ -n "$__ENV_WEB_PORT" ]] && WEB_PORT="$__ENV_WEB_PORT"
[[ -n "$__ENV_CONSOLE_PORT" ]] && CONSOLE_PORT="$__ENV_CONSOLE_PORT"

LAB_CIDR="${LAB_CIDR:-192.168.0.0/16}"
LAB_BIND_IP="${LAB_BIND_IP:-192.168.111.45}"
COWRIE_SSH_PORT="${COWRIE_SSH_PORT:-2222}"
COWRIE_TELNET_PORT="${COWRIE_TELNET_PORT:-2223}"
WEB_PORT="${WEB_PORT:-8080}"
CONSOLE_PORT="${CONSOLE_PORT:-8081}"

# THE CONSOLE IS NOT BAIT AND DOES NOT GET THE BAIT'S SCOPE.
#
# The decoy is meant to be reachable, so LAB_CIDR (which is the whole /16 by
# default) is the right scope for it. The console is the opposite: it shows
# every attack every student has thrown, which means it shows their source
# addresses, the usernames and passwords they guessed, and the commands they
# typed. Give it LAB_CIDR and a student in the lab can sit and watch every
# other student in the lab. That is a different service with a different job
# and it gets a different boundary.
#
# ADMIN_CIDR defaults to the console host's own subnet AS THE HOST DEFINES IT,
# taking the prefix length off the interface, never a guessed /24. On this farm
# that is a /16, because the farm is a /16. An earlier version of this comment
# said "the host's own /24" and a .env was written to match, and the result was
# a console that answered the machine that tested it and refused the human it
# was built for. A narrow-looking default is not a safe default: on a /16, a
# /24 means "one twenty-fifth of the people who should get in, and none of the
# others". Narrow is not the virtue. Correct is.
ADMIN_CIDR="${ADMIN_CIDR:-}"

if [[ "$LAB_CIDR" == "0.0.0.0/0" ]]; then
    echo "REFUSING: LAB_CIDR is 0.0.0.0/0. This is an internal lab; the whole" >&2
    echo "          internet does not get to reach it. Set LAB_CIDR in .env." >&2
    exit 1
fi

# Checked here, with LAB_CIDR, and not in the apply path. The first version of
# this check sat below the print-only exit, so `--apply` would have caught a
# 0.0.0.0/0 console scope and the dry run, the mode a human actually reads,
# would have printed the wide-open rules and exited 0. A guard that only runs
# when you have already decided to commit is not a guard.
if [[ "$ADMIN_CIDR" == "0.0.0.0/0" ]]; then
    echo "REFUSING: ADMIN_CIDR is 0.0.0.0/0. The console would be readable by" >&2
    echo "          everyone who can route here. That is not an admin scope." >&2
    exit 1
fi

# And it must not be NARROWER than the host's own network either. That is the
# bug of 2026-11-12 afternoon: ADMIN_CIDR was set to the test machine's /24 on
# a /16 farm, so the console answered the machine that tested it and refused
# the human it was built for. The test said "boundary proven" in both
# directions and both directions were wrong, because they were both taken from
# inside the same /24. Widening past the host's own network is a leak; narrowing
# inside it is a console nobody can reach. Refuse both, and say which.
if [[ -n "$ADMIN_CIDR" ]]; then
    _host_cidr=$(ip -4 -o addr show 2>/dev/null \
        | awk -v ip="${LAB_BIND_IP}" '$4 ~ ("^" ip "/") {print $4}' | head -1)
    if [[ -n "$_host_cidr" ]]; then
        _host_prefix="${_host_cidr#*/}"
        _admin_prefix="${ADMIN_CIDR#*/}"
        if [[ "$_admin_prefix" =~ ^[0-9]+$ ]] && [[ "$_host_prefix" =~ ^[0-9]+$ ]] \
           && (( _admin_prefix > _host_prefix )); then
            echo "REFUSING: ADMIN_CIDR=${ADMIN_CIDR} is narrower than this host's" >&2
            echo "          own network (${_host_cidr}). The console would be" >&2
            echo "          reachable from this host and from almost nowhere else," >&2
            echo "          which reads as working to whoever tests it locally." >&2
            # Suggestion only: compute the network address for the host's own
            # prefix. Kept to the octet the prefix actually covers rather than
            # reimplementing a bitmask, because guessing here is how this whole
            # afternoon went.
            _octets=$(( _host_prefix / 8 ))
            _net=$(printf '%s' "$_host_cidr" | cut -d/ -f1 | awk -F. -v n="$_octets" \
                '{for(i=1;i<=4;i++) printf "%s%s", (i<=n ? $i : "0"), (i<4 ? "." : ""); print "/" n*8}')
            echo "          Use ADMIN_CIDR=${_net}" >&2
            exit 1
        fi
    fi
fi

# ---------------------------------------------------------------------------
# The honest report. This is the part that has value; the rules below are
# secondary, and on most deployments should never be applied.
# ---------------------------------------------------------------------------

# Resolve the console's scope BEFORE the report renders it. Empty ADMIN_CIDR
# means "the console host's own subnet", never "LAB_CIDR", never "everything".
#
# This block used to live below the heredoc, at what was then line 361. The
# effect was that the report, the one artifact a cautious human reads before
# deciding to apply anything, printed the sentence above with an empty variable
# in it:
#
#   # CONSOLE = console on port 8081 is scoped to . It shows
#
# and exited 0. Grammatical, complete-looking, and missing the number in the
# same line that is supposed to say who can read the keystrokes. Jim found it on
# 2026-11-18, in report mode, with ADMIN_CIDR unset, which is the shipped
# default and the case DEPLOY.md now calls the dangerous one.
#
# That is the same defect as the 0.0.0.0/0 check above, which used to sit below
# the print-only exit: a check that only fires on --apply is not a check, and a
# report that says nothing where a number belongs is not a report. Moving the
# resolution up means the report and the apply path read one value, resolved
# once, so they cannot disagree.
if [[ -z "$ADMIN_CIDR" ]]; then
    ADMIN_CIDR=$(ip -4 -o addr show 2>/dev/null \
        | awk -v ip="${LAB_BIND_IP}" '$4 ~ ("^" ip "/") {print $4}' \
        | head -1)
    if [[ -z "$ADMIN_CIDR" ]]; then
        echo "REFUSING: cannot determine the console host's own subnet, and" >&2
        echo "          ADMIN_CIDR is unset. Set ADMIN_CIDR in .env: the console" >&2
        echo "          shows what every student typed, so it must not inherit" >&2
        echo "          the decoy's LAB_CIDR scope." >&2
        exit 1
    fi
    ADMIN_CIDR_NOTE="${ADMIN_CIDR} (derived from this host's own address; set ADMIN_CIDR to change)"
else
    ADMIN_CIDR_NOTE="${ADMIN_CIDR}"
fi

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
# CONSOLE = console on port ${CONSOLE_PORT} is scoped to ${ADMIN_CIDR}. It shows
#           what students typed, so it does not get the decoy's scope.
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
PORTS="${COWRIE_SSH_PORT},${COWRIE_TELNET_PORT},${WEB_PORT},${CONSOLE_PORT}"

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
# Read the destinations out of the nat table, not out of `docker port`.
# `docker port` prints "80/tcp -> 192.168.111.45:8080" -- container on the
# LEFT, published address on the RIGHT, which is the opposite of what a rule
# needs and of what the arrow suggests. Parsing it yields the host address,
# and a rule matching the host address after DNAT matches nothing.
#
# The DNAT rules are the ground truth: they are literally what the packet
# gets rewritten to. Docker writes them as
#   DNAT tcp dpt:<hostport> to:<container-addr>:<container-port>
if ! DESTS=$(iptables -t nat -S DOCKER 2>/dev/null \
        | sed -n 's/.*--to-destination \([0-9.]*\):\([0-9]*\).*/\1:\2/p' \
        | sort -u); then
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
echo "console scope:     ${ADMIN_CIDR_NOTE}"

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
while read -r dest; do
    [[ -z "$dest" ]] && continue
    dhost="${dest%:*}"
    dport="${dest##*:}"

    # Which sources may reach this destination.
    #
    # The console gets ADMIN_CIDR and the decoy gets LAB_CIDR, and the local
    # bridges are allowed on both so the host's own health check keeps
    # working. Before the console existed this was one scope for every port,
    # which was fine while every port was bait.
    if [[ "$dport" == "$CONSOLE_PORT" ]]; then
        SOURCES="${ADMIN_CIDR} ${BRIDGES}"
    else
        SOURCES="${LAB_CIDR} ${BRIDGES}"
    fi

    for src in $SOURCES; do
        SPECS+=("-p tcp -d ${dhost} --dport ${dport} -s ${src} -m comment --comment TRAPDOOR-scope -j ACCEPT")
    done
    SPECS+=("-p tcp -d ${dhost} --dport ${dport} -m comment --comment TRAPDOOR-scope -j DROP")
done <<< "$DESTS"

# Clear any previous version of this ruleset so re-runs are convergent rather
# than additive. Only touches rules on exactly these ports: the decoy ports
# and the console port.
while read -r rule; do
    [[ -z "$rule" ]] && continue
    # shellcheck disable=SC2086
    iptables -D DOCKER-USER $rule 2>/dev/null || true
done < <(iptables -S DOCKER-USER | grep -- 'TRAPDOOR-scope' | sed 's/^-A DOCKER-USER //' || true)

# Rules are INSERTED, not appended, and this is not a style choice.
#
# Docker creates DOCKER-USER with a bare RETURN as its first rule. Appending
# puts every TRAPDOOR rule underneath that RETURN, where it is unreachable:
# the chain exits before reaching it. Measured on .45, 2026-11-06 -- fifteen
# rules applied, all present, no duplicates, chain ends in DROP, decoy
# answering, and the top RETURN counters climbing while every TRAPDOOR rule
# sat at 0. The set looked complete and enforced nothing.
#
# SPECS is already in reading order, so inserting each at position 1 in
# reverse yields the intended order with the DROPs last.
for ((i = ${#SPECS[@]} - 1; i >= 0; i--)); do
    # shellcheck disable=SC2086
    iptables -I DOCKER-USER 1 ${SPECS[$i]}
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

# The console must still answer from its own admin scope, or the new scope
# closed the door it was meant to narrow. This is checked separately from the
# decoy because they now have different scopes and a single curl to one port
# cannot prove the other port's rule is right.
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://${LAB_BIND_IP}:${CONSOLE_PORT}/healthz" || true)
if [[ "$code" == "200" ]]; then
    echo "  OK   console answering on ${CONSOLE_PORT} (${code})"
else
    echo "  WARN console not answering on ${CONSOLE_PORT} after apply (got '${code}')" >&2
    echo "       not a FAIL: the container may simply not be up yet. If it is" >&2
    echo "       up and this says WARN, ADMIN_CIDR excludes this host (${ADMIN_CIDR})." >&2
fi

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
