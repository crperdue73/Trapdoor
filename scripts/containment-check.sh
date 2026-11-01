#!/usr/bin/env bash
# TRAPDOOR — host containment check (claim B5)
#
# WHAT THIS PROVES
#   That nothing typed into the decoy shell executes on the host.
#
# HOW
#   A canary string is generated fresh on every run and typed into the decoy
#   shell. Afterwards the host is searched for it. It should appear in exactly
#   one place: the Cowrie log. Anywhere else means the decoy is not a decoy.
#
# WHY THE CANARY IS GENERATED AND NOT FIXED
#   A fixed canary can be planted. Anyone who knows the string — including a
#   helpful colleague checking the box, or the author of this script six months
#   from now — can write it somewhere and turn a clean result into a false
#   alarm, or worse, make a real one look like a known artifact. Generating it
#   per run means the only way it appears somewhere is if the shell actually
#   executed.
#
#   This also means the canary is NEVER written to a file that persists, and
#   never transmitted. If you send someone "the canary," you have broken the
#   test. Send them the method and the search path instead.
#
# EXIT: 0 if contained, 1 if the canary escaped or the test could not run.
#
# Usage: ./scripts/containment-check.sh

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

# shellcheck disable=SC1091
[[ -f .env ]] && set -a && source .env && set +a

TARGET="${LAB_BIND_IP:-127.0.0.1}"
PORT="${COWRIE_SSH_PORT:-2222}"
USER="root"
PASS="toor"          # from cowrie/etc/userdb.txt; decoy credentials, not a secret

LOG="${COWRIE_LOG:-out/cowrie.log}"
EVENTS="${EVENTS:-out/events.jsonl}"

# Fresh, unguessable, per run. 12 hex chars is plenty: the search is for an
# exact string, not a pattern.
CANARY="TDCNRY$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-12)"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

command -v sshpass >/dev/null 2>&1 || { echo "sshpass required." >&2; exit 1; }

say "TRAPDOOR containment check"

# Fail early and loudly rather than reporting a pass on a test that never ran.
banner=$(timeout 5 nc -w 3 "$TARGET" "$PORT" </dev/null 2>/dev/null | head -1)
if [[ "$banner" != SSH-2.0-* ]]; then
    echo "  NOT RUN: no SSH banner on ${TARGET}:${PORT} — is the stack up?" >&2
    exit 1
fi

say "1. typing a canary into the decoy shell"
# The command is chosen so that IF it ran for real it would leave traces in
# obvious places: the shell history file and stdout. That gives the search
# below more than one place to find it, which makes a negative result stronger.
CANARY_CMD="echo ${CANARY} > /root/.canary-test; echo ${CANARY}"

out=$(SSHPASS="$PASS" timeout 20 sshpass -e ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o ConnectTimeout=5 \
        -o LogLevel=ERROR \
        -p "$PORT" "${USER}@${TARGET}" "$CANARY_CMD" 2>&1)
rc=$?

if [[ $rc -ne 0 ]]; then
    echo "  NOT RUN: could not open a decoy shell (rc=${rc})" >&2
    echo "  output: ${out:0:200}" >&2
    exit 1
fi

# Cowrie echoes the command back. We do NOT treat that as evidence of
# execution: echoing input is what a shell does, and what a fake shell also
# does. It proves the session worked, nothing more.
if grep -qF "$CANARY" <<<"$out"; then
    echo "  canary echoed by the decoy shell (expected — echoing is not executing)"
else
    echo "  NOTE: canary not echoed back. Session worked but output may be suppressed."
fi

say "2. searching the host for it"
# Search the filesystem but skip the places the canary is SUPPOSED to be:
# the Cowrie log and the event pipeline output.
ESCAPED=0
HITS=0

search_paths=("/root" "/tmp" "/var/tmp" "/home" "/etc" "/opt" "/srv")
for p in "${search_paths[@]}"; do
    [[ -d "$p" ]] || continue
    hits=$(grep -rlF "$CANARY" "$p" 2>/dev/null | grep -vE "/(out)/" || true)
    if [[ -n "$hits" ]]; then
        echo "  LEAKED in ${p}:" >&2
        echo "$hits" | sed 's/^/    /' >&2
        ESCAPED=1
        HITS=$((HITS + $(echo "$hits" | wc -l)))
    fi
done

# The decoy's own record. The canary SHOULD be here — that is the point of the
# exercise, and finding it here is what proves the logging works.
if [[ -f "$LOG" ]] && grep -qF "$CANARY" "$LOG" 2>/dev/null; then
    echo "  found in the Cowrie log (correct — it was logged, not executed)"
elif [[ -f "$EVENTS" ]] && grep -qF "$CANARY" "$EVENTS" 2>/dev/null; then
    echo "  found in events.jsonl (correct — it was logged, not executed)"
else
    echo "  WARNING: canary not found in the log either." >&2
    echo "  That means the shell worked but nothing recorded it — a logging gap." >&2
    ESCAPED=1
fi

say "3. result"
if [[ "$ESCAPED" -eq 0 ]]; then
    echo "  CONTAINED. The canary was typed, was logged, and executed nowhere."
    echo "  No command typed into the decoy reached this host."
    echo
    echo "  Canary is not printed and is not stored. It existed for this run and"
    echo "  for no other. To repeat the test, run this again — a new one is made."
    exit 0
else
    echo "  NOT CONTAINED — the canary appeared outside the log (${HITS} location(s))." >&2
    echo "  The decoy shell executed a real command on this host." >&2
    echo "  Do not call this deployed. Investigate before anything else." >&2
    exit 1
fi
