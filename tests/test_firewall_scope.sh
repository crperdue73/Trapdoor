#!/usr/bin/env bash
# Tests for the console's firewall scope.
#
# Why this file exists: on 2026-11-12 the console was published on 8081 and
# neither firewall.sh nor verify.sh knew the port existed. The decoy's ports
# were covered and the new thing was not, which is the same shape as every
# other bug in this repo: the thing that reports is not the thing that runs.
#
# These tests run the script in print mode with no root and no iptables. They
# assert on what it SAYS, because what a firewall script says is the only part
# a student can read before deciding whether to apply it.
#
# Nothing here touches a host. That is deliberate: these must pass on a
# laptop, in CI, on a fresh LXC with no Docker, and on the honeypot itself.

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

PASS=0
FAIL=0

ok()   { echo "  PASS $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $*"; FAIL=$((FAIL+1)); }

# Print mode, explicit env, so the test does not depend on a local .env.
run() {
    LAB_CIDR="${1}" ADMIN_CIDR="${2}" LAB_BIND_IP="${3}" \
        bash scripts/firewall.sh 2>&1
}

echo "firewall console scope"

# --- 1. the console port appears at all ------------------------------------
# The original bug. If 8081 is absent from the output, the report is silent
# about a published port and the reader cannot know it is unscoped.
out=$(run 10.20.30.0/24 192.168.111.0/24 192.168.111.45)
if printf '%s' "$out" | grep -q "8081"; then
    ok "console port 8081 is named in the report"
else
    bad "console port 8081 is missing from the report (the 2026-11-12 bug)"
fi

# --- 2. the console gets its own scope, not the decoy's --------------------
if printf '%s' "$out" | grep -qE "console on port 8081 is scoped to 192\.168\.111\.0/24"; then
    ok "console reports its own ADMIN_CIDR scope"
else
    bad "console does not report its own scope"
fi

# --- 3. the two scopes are visibly different -------------------------------
# A reader must be able to see that the decoy and the console are bounded
# differently. One scope line for both is how the split silently dies.
if printf '%s' "$out" | grep -q "LAB_CIDR = 10.20.30.0/24" \
   && printf '%s' "$out" | grep -q "scoped to 192.168.111.0/24"; then
    ok "decoy and console scopes are reported separately"
else
    bad "scopes are not reported separately"
fi

# --- 4. a wide-open admin scope is refused in print mode -------------------
# The first version of this guard sat below the print-only exit, so the dry
# run printed the wide-open rules and exited 0. The dry run is the mode a
# human reads before deciding, so the guard has to hold there.
run 10.20.30.0/24 0.0.0.0/0 192.168.111.45 >/dev/null 2>&1
rc=$?
if [[ $rc -ne 0 ]]; then
    ok "ADMIN_CIDR=0.0.0.0/0 refused in print mode (rc=${rc})"
else
    bad "ADMIN_CIDR=0.0.0.0/0 was printed without complaint (rc=0)"
fi

# --- 5. a wide-open lab scope is still refused -----------------------------
run 0.0.0.0/0 192.168.111.0/24 192.168.111.45 >/dev/null 2>&1
rc=$?
if [[ $rc -ne 0 ]]; then
    ok "LAB_CIDR=0.0.0.0/0 still refused (rc=${rc})"
else
    bad "LAB_CIDR=0.0.0.0/0 was accepted"
fi

# --- 6. the refusal is explained, not just a number ------------------------
msg=$(run 10.20.30.0/24 0.0.0.0/0 192.168.111.45)
if printf '%s' "$msg" | grep -q "not an admin scope"; then
    ok "the refusal says why"
else
    bad "the refusal gives no reason"
fi

# --- 7. an unset ADMIN_CIDR does not become 'everything' -------------------
# Empty means "derive from this host", never LAB_CIDR. Asserting the absence
# of a bad default is worth a test because the bad default is convenient.
out2=$(LAB_CIDR=10.20.30.0/24 LAB_BIND_IP=192.168.111.45 bash scripts/firewall.sh 2>&1)
if printf '%s' "$out2" | grep -q "console on port 8081 is scoped to 10.20.30.0/24"; then
    bad "unset ADMIN_CIDR silently inherited LAB_CIDR"
else
    ok "unset ADMIN_CIDR does not inherit LAB_CIDR"
fi

# --- 8. a scope NARROWER than the host's own network is refused ------------
# The 2026-11-12 afternoon bug. ADMIN_CIDR was set to the test machine's /24
# on a /16 farm. The console answered the machine that tested it and refused
# the human it was built for, and both directions of the "boundary proof" were
# taken from inside the same /24, so both were wrong.
#
# This needs LAB_BIND_IP to actually be an address on this machine, so it only
# runs where that is true. Skipping is honest; silently passing is not.
BIND_IP=$(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
if [[ -n "$BIND_IP" ]]; then
    HOSTPFX=$(ip -4 -o addr show 2>/dev/null | awk -v ip="$BIND_IP" '$4 ~ ("^" ip "/") {print $4}' | head -1 | cut -d/ -f2)
    if [[ "$HOSTPFX" =~ ^[0-9]+$ ]] && (( HOSTPFX < 32 )); then
        NARROW="$BIND_IP/$((HOSTPFX + 1))"
        run 10.20.30.0/24 "$NARROW" "$BIND_IP" >/dev/null 2>&1
        rc=$?
        if [[ $rc -ne 0 ]]; then
            ok "a scope narrower than the host's own network is refused"
        else
            bad "a /$((HOSTPFX + 1)) console scope on a /$HOSTPFX host was accepted"
        fi
        msg=$(run 10.20.30.0/24 "$NARROW" "$BIND_IP")
        if printf '%s' "$msg" | grep -q "narrower than this host"; then
            ok "the too-narrow refusal explains itself"
        else
            bad "the too-narrow refusal gives no reason"
        fi
    else
        echo "  SKIP narrower-than-host check (no usable prefix on this machine)"
    fi
else
    echo "  SKIP narrower-than-host check (no IPv4 address found)"
fi

# ---------------------------------------------------------------------------
# The report must never print a scope it has not resolved.
#
# Found by Jim on 2026-11-18, in report mode, with ADMIN_CIDR unset (the shipped
# default). The report said:
#
#   # CONSOLE = console on port 8081 is scoped to . It shows
#
# and exited 0. The derivation ran about 140 lines further down, so the one
# artifact a cautious human reads before applying anything printed a sentence
# with the number missing, in the middle of the sentence that is supposed to say
# who can read student keystrokes. A blank there does not read as "unknown". It
# reads as "nothing to worry about".
#
# This is the same shape as the 0.0.0.0/0 guard that used to sit below the
# print-only exit. Assertions below are cheap and they are the kind that would
# have caught it: the report either states a scope, or it refuses out loud.
# It may not state an empty one.
# ---------------------------------------------------------------------------
echo

# Pick an address that actually exists on this box, so the derived path can
# resolve. Tests must not depend on a specific host's IP.
_HERE_IP=$(ip -4 -o addr show 2>/dev/null \
    | awk '$2 != "lo" && $4 !~ /^127\./ {sub(/\/.*/,"",$4); print $4; exit}')

if [[ -z "$_HERE_IP" ]]; then
    echo "  SKIP report-never-blank (no non-loopback IPv4 on this machine)"
else
    # 1. ADMIN_CIDR unset: the report must still name a scope, not a blank.
    _out=$(ADMIN_CIDR= LAB_BIND_IP="$_HERE_IP" bash scripts/firewall.sh 2>&1)
    _rc=$?
    if [[ $_rc -ne 0 ]]; then
        # A refusal is an acceptable answer, and it must say why.
        if printf '%s' "$_out" | grep -qi "REFUSING"; then
            ok "report with ADMIN_CIDR unset either resolves the scope or refuses out loud"
        else
            bad "report with ADMIN_CIDR unset exited $_rc without saying REFUSING"
        fi
    else
        _line=$(printf '%s\n' "$_out" | grep "is scoped to" | head -1)
        if [[ -z "$_line" ]]; then
            bad "report with ADMIN_CIDR unset has no console scope line at all"
        elif printf '%s' "$_line" | grep -qE "is scoped to \. ?It shows"; then
            bad "report printed a BLANK console scope: '${_line}'"
        elif printf '%s' "$_line" | grep -qE "is scoped to [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+"; then
            ok "report with ADMIN_CIDR unset names the derived scope instead of a blank"
        else
            bad "report scope line has an unparseable scope: '${_line}'"
        fi
    fi

    # 2. ADMIN_CIDR set: the report must echo exactly that value.
    #    The value must not be narrower than this host's own network or the
    #    script refuses it, correctly. Derive a legal one from the host itself
    #    so this test does not encode one machine's addressing.
    _scope=$(ip -4 -o addr show 2>/dev/null \
        | awk -v ip="$_HERE_IP" '$4 ~ ("^" ip "/") {print $4; exit}')
    if [[ -z "$_scope" ]]; then
        echo "  SKIP report-echoes-scope (could not derive this host's prefix)"
    else
        _out=$(ADMIN_CIDR="$_scope" LAB_BIND_IP="$_HERE_IP" bash scripts/firewall.sh 2>&1)
        if printf '%s' "$_out" | grep -qF "is scoped to ${_scope}"; then
            ok "report echoes the explicitly set console scope (${_scope})"
        else
            bad "report does not echo an explicitly set ADMIN_CIDR=${_scope}"
        fi
    fi
fi

echo
if [[ $FAIL -eq 0 ]]; then
    echo "PASS  $PASS console-scope tests"
    exit 0
else
    echo "FAIL  $FAIL of $((PASS+FAIL)) console-scope tests"
    exit 1
fi
