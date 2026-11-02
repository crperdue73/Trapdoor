#!/usr/bin/env bash
# TRAPDOOR — SSH brute-force scenario
#
# WHAT THIS IS
#   A scripted credential-stuffing attack against the Cowrie decoy. It tries a
#   fixed list of username/password pairs in a fixed order, at a fixed pace, so
#   every student who runs it gets the same transcript.
#
# WHY SCRIPTED AND NOT nmap/hydra
#   Reproducibility beats realism here. A student comparing their log to the
#   slides needs the same events in the same order. Hydra with random timing
#   produces a different lesson every time.
#
# WHAT IT PROVES (checkable claims, not a story)
#   1. An unauthenticated TCP connection to :2222 yields an SSH-2.0 banner.
#   2. A failed login is logged as cowrie.login.failed with the username.
#   3. A successful login is logged as cowrie.login.success.
#   4. Commands run after login are logged as cowrie.command.input.
#   5. Attacker commands do NOT execute on the host. Ever.
#
# Usage: ./scenarios/ssh-bruteforce.sh [target] [port]

set -uo pipefail

# shellcheck disable=SC1091
[[ -f .env ]] && set -a && source .env && set +a

TARGET="${1:-${LAB_BIND_IP:-127.0.0.1}}"
PORT="${2:-${COWRIE_SSH_PORT:-2222}}"

# The fixed credential list. Same order every run, same lesson every time.
#
# TWO THINGS THIS LIST HAS TO GET RIGHT, both learned the hard way:
#
# 1. It must contain rejected attempts BEFORE the accepted one. An earlier
#    version had "root:123456" first — and 123456 IS in userdb.txt, so the
#    scenario authenticated on attempt #1, printed ACCEPTED, and dropped into
#    the shell. The lesson is "watch a brute force fail, fail, fail, then get
#    in." It was showing one success and zero failures. The transcript looked
#    fine and taught the opposite of the lesson.
#
# 2. Exactly one entry may be in userdb.txt. If nobody wrote this list down
#    next to that file, the two drift apart and nobody notices, because a
#    success where you expected a failure is not an error condition — it is
#    just a different lesson.
#
# Claim 2 below therefore checks the list against userdb.txt before running
# anything, and fails loudly if the shape is wrong.
CREDS=(
  "root:password"     # expected: rejected
  "admin:123456"      # expected: rejected
  "root:guess123"     # expected: rejected
  "admin:letmein"     # expected: rejected
  "ubuntu:changeme"   # expected: rejected
  "root:toor"         # expected: ACCEPTED (present in cowrie/etc/userdb.txt)
)

# Header helper defined before anything uses it. It lived below claim 0 for
# one commit and every scenario run opened with "say: command not found" —
# harmless, invisible if you only read the parts you expected to see, and
# exactly the kind of stderr noise that teaches students to ignore stderr.
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# --- claim 0: the list has the shape the lesson needs ----------------------
# This is the guard that turns "the transcript looks fine" into a check.
say "0. credential list matches the decoy's userdb"
USERDB="${USERDB:-cowrie/etc/userdb.txt}"
if [[ ! -f "$USERDB" ]]; then
    echo "   FAIL: cannot read ${USERDB} — no way to know which attempts will" >&2
    echo "   succeed, so the lesson cannot be trusted. Aborting." >&2
    exit 1
fi

EXPECTED_FAIL=0
EXPECTED_OK=0
MISMATCH=0
for cred in "${CREDS[@]}"; do
    u="${cred%%:*}"; p="${cred#*:}"
    if grep -qx "${u}:x:${p}" "$USERDB"; then
        echo "   in userdb, will authenticate:  ${u}:${p}"
        EXPECTED_OK=$((EXPECTED_OK + 1))
    else
        EXPECTED_FAIL=$((EXPECTED_FAIL + 1))
    fi
done
echo "   ${EXPECTED_FAIL} expected failures, ${EXPECTED_OK} expected success"

if [[ "$EXPECTED_OK" -eq 0 ]]; then
    echo "   FAIL: every credential in this list is rejected — the scenario" >&2
    echo "   would never reach the shell. Add one entry present in userdb." >&2
    exit 1
fi
if [[ "$EXPECTED_OK" -gt 1 ]]; then
    echo "   FAIL: ${EXPECTED_OK} credentials in this list will authenticate." >&2
    echo "   The lesson is one break-in after several failures; more than one" >&2
    echo "   success makes the transcript misleading." >&2
    exit 1
fi
if [[ "$EXPECTED_FAIL" -eq 0 ]]; then
    echo "   FAIL: no attempt will fail. A brute force that succeeds first try" >&2
    echo "   is not a brute force and the lesson shows nothing." >&2
    exit 1
fi
# The single success must be LAST, or the loop breaks before showing failures.
last="${CREDS[${#CREDS[@]}-1]}"
lu="${last%%:*}"; lp="${last#*:}"
if ! grep -qx "${lu}:x:${lp}" "$USERDB"; then
    echo "   FAIL: the last entry (${lu}) is not the one in userdb, but the" >&2
    echo "   loop stops at the first success — so the failures after it are" >&2
    echo "   never shown. Put the accepted credential last." >&2
    exit 1
fi
for cred in "${CREDS[@]:0:${#CREDS[@]}-1}"; do
    u="${cred%%:*}"; p="${cred#*:}"
    if grep -qx "${u}:x:${p}" "$USERDB"; then
        echo "   FAIL: ${u} authenticates but is not last in the list. The" >&2
        echo "   scenario would stop here and skip the remaining attempts." >&2
        exit 1
    fi
done
echo "   OK: shape is correct"

command -v sshpass >/dev/null 2>&1 || {
    echo "sshpass is required (apt install sshpass)." >&2
    echo "It is only used to drive the scripted logins; nothing else needs it." >&2
    exit 1
}

say "TRAPDOOR scenario: ssh-bruteforce"
echo "target ${TARGET}:${PORT}"
echo "attempts: ${#CREDS[@]}"
echo
echo "This attacks a decoy. Every login lands in a fake filesystem and nothing"
echo "typed here executes anywhere. That is the point of the exercise."
echo

# --- claim 1: the banner ---------------------------------------------------
say "1. banner"
banner=$(timeout 5 nc -w 3 "$TARGET" "$PORT" </dev/null 2>/dev/null | head -1)
if [[ "$banner" == SSH-2.0-* ]]; then
    echo "   ${banner}"
else
    echo "   FAIL: no SSH banner on ${TARGET}:${PORT}" >&2
    echo "   is the stack up? try: make ps" >&2
    exit 1
fi

# --- claims 2 and 3: the attempts -----------------------------------------
say "2. credential attempts"
SUCCESS=""
for cred in "${CREDS[@]}"; do
    user="${cred%%:*}"
    pass="${cred#*:}"

    # BatchMode off, strict host key off (nobody has ever verified a honeypot's
    # host key and pretending otherwise in a script is theatre), short timeout.
    out=$(SSHPASS="$pass" timeout 10 sshpass -e ssh \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o PreferredAuthentications=password \
            -o PubkeyAuthentication=no \
            -o ConnectTimeout=5 \
            -o LogLevel=ERROR \
            -p "$PORT" "${user}@${TARGET}" 'true' 2>&1)
    rc=$?

    if [[ $rc -eq 0 ]]; then
        printf '   \033[32mACCEPTED\033[0m  %-8s %s\n' "$user" "$pass"
        SUCCESS="$user:$pass"
        break
    else
        printf '   \033[31mREJECTED\033[0m  %-8s %s\n' "$user" "$pass"
    fi

    # A deliberate pause. A real brute force is loud and fast; this one is paced
    # so the event timestamps in the resulting log are readable when projected
    # on a classroom screen. Note it in the lesson: real attacks do not wait.
    sleep 1
done

# --- claim 4: shell interaction -------------------------------------------
if [[ -n "$SUCCESS" ]]; then
    user="${SUCCESS%%:*}"
    pass="${SUCCESS#*:}"
    say "3. shell session as ${user}"

    # These commands are chosen to be the ones a real attacker types first.
    # Each one is logged individually as cowrie.command.input, which is what
    # makes the transcript useful for teaching.
    COMMANDS='id; uname -a; cat /etc/passwd; ls -la /; echo "TRAPDOOR-CANARY"'

    SSHPASS="$pass" timeout 20 sshpass -e ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o ConnectTimeout=5 \
        -o LogLevel=ERROR \
        -p "$PORT" "${user}@${TARGET}" "$COMMANDS" 2>&1 | sed 's/^/   /'

    echo
    echo "   Every line above came from Cowrie's emulated shell. No command ran"
    echo "   on any real system."
else
    say "3. no credential accepted"
    echo "   Set auth_class = UserDB in cowrie/etc/cowrie.cfg and make sure"
    echo "   root/toor is present in cowrie/etc/userdb.txt."
fi

# --- claim 5: what to look for in the events ------------------------------
say "4. what to check in out/events.jsonl"
cat <<'HINT'
   jq -r 'select(.sensor=="cowrie") | [.ts, .event_type, .username] | @tsv' \
      out/events.jsonl | tail -20

   Expect, in order:
     cowrie.session.connect
     cowrie.login.failed      (one per rejected pair)
     cowrie.login.success     (once)
     cowrie.command.input     (id, uname, cat, ls, echo)
     cowrie.session.closed
HINT

say "done"
