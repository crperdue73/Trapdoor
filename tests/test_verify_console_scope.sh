#!/usr/bin/env bash
# Tests for verify.sh check 8: the console's scope assertion.
#
# WHY THIS FILE EXISTS, AND WHY IT CHANGED ON 2026-11-18
#
# Check 8 was written on 2026-11-12 to catch the console being as open as the
# bait. The first version hard-coded "console scoped to 192.168.0.0/16 = FAIL",
# which on a farm whose network IS the /16 fails the only configuration that
# exists.
#
# Then I "fixed" it to fail any prefix <= 16 for being "as wide as the farm".
# That is the same mistake one level down. It assumes a narrow operator network
# EXISTS to narrow to. On this deployment it does not: one network, the whole
# IT department on a single /16, no student VLAN. So the check failed the
# correct deployment on every run, forever, and a check that cannot pass is a
# check nobody reads. That is the same lie as a check that cannot fail,
# arriving from the other direction.
#
# THE CHECK NOW ASKS A QUESTION THAT CAN BE WRONG TWICE:
#
#   1. Is the console's real scope DECLARED in writing, by a human, naming who
#      is on the network? Undeclared = unowned. FAIL.
#   2. Has the console drifted WIDER than that declaration? That is a leak of
#      what students typed to people the declaration does not cover. FAIL.
#
# A /16 declared as "entire IT department, no student VLAN" passes honestly.
# The same /16 with nobody having said so does not. Narrower than declared is
# a warning, not a leak: the 2026-11-12 afternoon proved a narrow-looking
# default can lock out the human it was built for.
#
# Vera's rule still holds and is still tested here: a skipped check is not a
# passed check.
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
#
# $4 = CONSOLE_NETWORK_DECLARED (may be empty, which is itself the test)
run_check8() {
    local fixture="$1" admin="$2" lab="$3" declared="${4-}"
    IPTABLES_FIXTURE="$fixture" \
    PATH="$TMP/bin:$PATH" \
    ADMIN_CIDR="$admin" LAB_CIDR="$lab" CONSOLE_PORT=8081 \
    CONSOLE_NETWORK_DECLARED="$declared" \
        bash scripts/verify.sh 2>&1
}

plain() { printf '%s' "$1" | sed 's/\x1b\[[0-9;]*m//g'; }

# Fixture A: console wide open to the farm /16 (the real 2026-11-12 state)
cat > "$TMP/wide.txt" <<'EOF'
-A DOCKER-USER -s 192.168.0.0/16 -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j ACCEPT
-A DOCKER-USER -s 172.23.0.1/32 -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j ACCEPT
-A DOCKER-USER -s 172.22.0.1/32 -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j ACCEPT
-A DOCKER-USER -s 172.17.0.1/32 -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j ACCEPT
-A DOCKER-USER -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j DROP
EOF

# Fixture B: console narrowed to an operator subnet
cat > "$TMP/narrow.txt" <<'EOF'
-A DOCKER-USER -s 192.168.111.0/24 -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j ACCEPT
-A DOCKER-USER -s 172.23.0.1/32 -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j ACCEPT
-A DOCKER-USER -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j DROP
EOF

# Fixture C: no console rules at all (firewall never applied since the console
# was added) - must not pass silently
: > "$TMP/empty.txt"

# Fixture D: a /8, wider than any plausible declaration
cat > "$TMP/slash8.txt" <<'EOF'
-A DOCKER-USER -s 192.0.0.0/8 -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j ACCEPT
-A DOCKER-USER -d 172.22.0.3/32 -p tcp -m tcp --dport 8081 -m comment --comment TRAPDOOR-scope -j DROP
EOF

echo "check 8: console scope assertion"

# 1. THE HONEST /16. A farm-wide console that is DECLARED farm-wide must pass.
#    This is the deployment that exists, and the old check failed it every run.
out=$(plain "$(run_check8 "$TMP/wide.txt" "192.168.0.0/16" "192.168.0.0/16" \
    "192.168.0.0/16|entire IT department, single network, no student VLAN")")
if printf '%s' "$out" | grep -q "OK.*console scope 192.168.0.0/16 matches the declared operator network"; then
    ok "a declared /16 console PASSES (single network, stated honestly)"
else
    bad "a declared /16 console did not pass; got: $(printf '%s' "$out" | grep -i 'console' | head -3)"
fi

# 2. ...and it must not carry a FAIL line while passing.
if printf '%s' "$out" | grep -q "FAIL console accepts"; then
    bad "a declared /16 passed but still printed a failure (contradictory verdict)"
else
    ok "no contradictory failure alongside the declared-/16 pass"
fi

# 3. THE SAME /16 WITH NO DECLARATION MUST FAIL. Undeclared = unowned. This is
#    what keeps the check from being theater after the /16 became legal.
out=$(plain "$(run_check8 "$TMP/wide.txt" "192.168.0.0/16" "192.168.0.0/16" "")")
if printf '%s' "$out" | grep -q "FAIL console accepts 192.168.0.0/16 and NO operator network is declared"; then
    ok "an undeclared farm-wide console FAILS"
else
    bad "an undeclared /16 console did not fail; got: $(printf '%s' "$out" | grep -i 'console' | head -3)"
fi

# 4. The failure must say what to change, not just print FAIL.
if printf '%s' "$out" | grep -q "Set CONSOLE_NETWORK_DECLARED"; then
    ok "the undeclared failure says what to change"
else
    bad "the undeclared failure does not say what to change"
fi

# 5. DRIFT WIDER THAN THE DECLARATION. Console accepts /8 while the declaration
#    says /16: the console reports on people nobody said could read it.
out=$(plain "$(run_check8 "$TMP/slash8.txt" "192.0.0.0/8" "192.168.0.0/16" \
    "192.168.0.0/16|entire IT department, single network, no student VLAN")")
if printf '%s' "$out" | grep -q "FAIL console accepts 192.0.0.0/8, WIDER than the declared operator"; then
    ok "a console wider than its declaration FAILS"
else
    bad "a /8 console against a /16 declaration did not fail; got: $(printf '%s' "$out" | grep -i 'console' | head -3)"
fi

# 6. A declaration that does not parse is a broken declaration, not a pass.
out=$(plain "$(run_check8 "$TMP/wide.txt" "192.168.0.0/16" "192.168.0.0/16" \
    "the whole IT network|entire IT department")")
if printf '%s' "$out" | grep -q "FAIL CONSOLE_NETWORK_DECLARED is set but its CIDR does not parse"; then
    ok "an unparseable declaration FAILS rather than passing"
else
    bad "a malformed declaration did not fail; got: $(printf '%s' "$out" | grep -i 'declared' | head -3)"
fi

# 7. Narrower than declared is a warning, not a leak. It must not fail, because
#    2026-11-12 proved a narrow-looking default locks out the human it is for.
out=$(plain "$(run_check8 "$TMP/narrow.txt" "192.168.111.0/24" "192.168.0.0/16" \
    "192.168.0.0/16|entire IT department, single network, no student VLAN")")
if printf '%s' "$out" | grep -q "NARROWER than declared"; then
    ok "a console narrower than its declaration is warned about"
else
    bad "a narrower-than-declared console said nothing; got: $(printf '%s' "$out" | grep -i 'console' | head -3)"
fi
if printf '%s' "$out" | grep -q "FAIL console accepts"; then
    bad "narrower than declared FAILED the check; it is not a leak and must not fail"
else
    ok "narrower than declared does not fail the check"
fi

# 8. No console rules at all: must be surfaced as NOT RUN, never as a pass.
out=$(plain "$(run_check8 "$TMP/empty.txt" "192.168.111.0/24" "192.168.0.0/16" \
    "192.168.0.0/16|entire IT department")")
if printf '%s' "$out" | grep -q "NOT RUN.*console scope"; then
    ok "an un-auditable console is reported NOT RUN, not passed"
else
    bad "with no console rules the check said nothing about it (silent pass)"
fi

# 9. A NOT RUN must fail the overall run (Vera's rule, 2026-11-01).
if printf '%s' "$out" | grep -q "A skipped check is not a passed check"; then
    ok "a skipped console check fails the overall verdict and says so"
else
    bad "a skipped console check did not fail the run with an explanation"
fi

echo
if [[ $FAIL -eq 0 ]]; then
    echo "PASS  $PASS verify-check-8 tests"
    exit 0
else
    echo "FAIL  $FAIL of $((PASS+FAIL)) verify-check-8 tests"
    exit 1
fi
