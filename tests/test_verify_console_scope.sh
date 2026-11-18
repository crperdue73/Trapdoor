#!/usr/bin/env bash
# Tests for verify.sh check 8: the console's scope assertion.
#
# WHY THIS FILE EXISTS
#
# Check 8 was written on 2026-11-12 to catch the console being as open as the
# bait. The first version asserted the wrong thing: it hard-coded "console
# scoped to 192.168.0.0/16 = FAIL", which on a farm whose network IS the /16
# means the check fails the correct configuration. I then discovered the real
# defect it had been pointing at (LAB_CIDR and ADMIN_CIDR were both the /16, so
# the console genuinely had no narrower scope) and almost "fixed" the check to
# go green instead of reading it.
#
# So these tests pin down BOTH directions:
#   - a console scoped to the whole farm MUST fail
#   - a console scoped narrower MUST pass
#   - an unparseable/absent rule set MUST be reported as NOT RUN, not passed
#
# That third one is Vera's rule: a skipped check is not a passed check.
#
# HOW. verify.sh reads `iptables -S DOCKER-USER`. These tests do not touch a
# host, so they put a fake `iptables` on PATH that prints fixture rules. That
# keeps the whole thing runnable on a laptop with no Docker and no root.

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

PASS=0
FAIL=0
ok()  { echo "  PASS $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL $*"; FAIL=$((FAIL+1)); }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"

# fake iptables: prints whatever is in the fixture file, ignores arguments
cat > "$TMP/bin/iptables" <<'FAKE'
#!/bin/sh
cat "$IPTABLES_FIXTURE" 2>/dev/null
exit 0
FAKE
chmod +x "$TMP/bin/iptables"

# Run only check 8 by feeding verify.sh a fixture and reading its section-8
# output. verify.sh runs many checks that need a real host; those will warn or
# skip, which is fine. We assert only on the console-scope lines.
run_check8() {
    local fixture="$1" admin="$2" lab="$3"
    IPTABLES_FIXTURE="$fixture" \
    PATH="$TMP/bin:$PATH" \
    ADMIN_CIDR="$admin" LAB_CIDR="$lab" CONSOLE_PORT=8081 \
        bash scripts/verify.sh 2>&1
}

# Fixture A: console wide open to the farm /16 (the real 2026-11-12 state)
cat > "$TMP/wide.txt" <<'EOF'
-A DOCKER-USER -s 192.168.0.0/16 -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j ACCEPT
-A DOCKER-USER -s 172.23.0.1/32 -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j ACCEPT
-A DOCKER-USER -s 172.22.0.1/32 -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j ACCEPT
-A DOCKER-USER -s 172.17.0.1/32 -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j ACCEPT
-A DOCKER-USER -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j DROP
EOF

# Fixture B: console correctly narrowed to an operator subnet
cat > "$TMP/narrow.txt" <<'EOF'
-A DOCKER-USER -s 192.168.111.0/24 -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j ACCEPT
-A DOCKER-USER -s 172.23.0.1/32 -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j ACCEPT
-A DOCKER-USER -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j DROP
EOF

# Fixture C: no console rules at all (firewall never applied since the console
# was added) - must not pass silently
: > "$TMP/empty.txt"

echo "check 8: console scope assertion"

# 1. The whole-farm scope must FAIL. This is the real defect from 2026-11-12.
out=$(run_check8 "$TMP/wide.txt" "192.168.0.0/16" "192.168.0.0/16")
if printf '%s' "$out" | grep -q "FAIL console accepts 192.168.0.0/16"; then
    ok "a console scoped to the whole farm FAILS"
else
    bad "a /16 console scope did not fail; output was: $(printf '%s' "$out" | grep -i console | head -3)"
fi

# 2. The failure must explain itself, not just print FAIL.
if printf '%s' "$out" | grep -q "Set ADMIN_CIDR to the operator network"; then
    ok "the wide-scope failure says what to change"
else
    bad "the wide-scope failure does not say what to change"
fi

# 3. A narrowed console must PASS. This is the direction my first version of
#    the check got wrong: it failed the correct configuration.
out=$(run_check8 "$TMP/narrow.txt" "192.168.111.0/24" "192.168.0.0/16")
# verify.sh colours its OK marker, so strip escapes before matching.
out_plain=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g')
if printf '%s' "$out_plain" | grep -q "OK    console scope 192.168.111.0/24 is narrower than the farm"; then
    ok "a narrowed console PASSES on a farm-wide network"
else
    bad "a /24 console scope on a /16 farm did not pass; got: $(printf '%s' "$out" | grep -i "console scope" | head -2)"
fi

# 4. ...and it must not ALSO print the /16 failure while passing the /24.
if printf '%s' "$out" | grep -q "FAIL console accepts"; then
    bad "a narrowed console still reported the wide-scope failure (contradictory verdict)"
else
    ok "no contradictory failure alongside the pass"
fi

# 5. No console rules at all: must be surfaced as NOT RUN, never as a pass.
out=$(run_check8 "$TMP/empty.txt" "192.168.111.0/24" "192.168.0.0/16")
if printf '%s' "$out" | grep -q "NOT RUN.*console scope"; then
    ok "an un-auditable console is reported NOT RUN, not passed"
else
    bad "with no console rules the check said nothing about it (silent pass)"
fi

# 6. A NOT RUN must fail the overall run (Vera's rule, 2026-11-01).
if printf '%s' "$out" | grep -q "A skipped check is not a passed check"; then
    ok "a skipped console check fails the overall verdict and says so"
else
    bad "a skipped console check did not fail the run with an explanation"
fi

# 7. Guard against the anti-pattern: the literal /16 must no longer be the
#    sole basis for failing. A /16 farm with a /16 console fails (test 1), but
#    a /24 farm with a /16 console must ALSO fail, and it must fail on scope
#    width, not on string equality.
out=$(run_check8 "$TMP/wide.txt" "192.168.0.0/16" "192.168.111.0/24")
if printf '%s' "$out" | grep -q "FAIL console accepts 192.168.0.0/16"; then
    ok "scope width is judged by prefix length, not by the literal farm string"
else
    bad "the check still depends on matching a literal /16 string"
fi

# 8. A /8 console scope (wider than the farm) must fail too.
cat > "$TMP/slash8.txt" <<'EOF'
-A DOCKER-USER -s 192.0.0.0/8 -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j ACCEPT
-A DOCKER-USER -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j DROP
EOF
out=$(run_check8 "$TMP/slash8.txt" "192.168.0.0/16" "192.168.0.0/16")
if printf '%s' "$out" | grep -q "FAIL console accepts 192.0.0.0/8"; then
    ok "a /8 console scope fails (wider than the farm)"
else
    bad "a /8 console scope did not fail"
fi

echo
if [[ $FAIL -eq 0 ]]; then
    echo "PASS  $PASS verify-check-8 tests"
    exit 0
else
    echo "FAIL  $FAIL of $((PASS+FAIL)) verify-check-8 tests"
    exit 1
fi
