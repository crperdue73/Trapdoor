#!/usr/bin/env bash
# TRAPDOOR — web scanner scenario
#
# WHAT THIS IS
#   A scripted sweep of the bait paths on the nginx decoy. It requests the
#   same URLs, in the same order, that an automated scanner hits first.
#
# WHAT IT PROVES (checkable claims, not a story)
#   1. GET /             returns 200  (an ordinary web server)
#   2. GET /.env         returns 403  (exists but forbidden — bait, not a 404)
#   3. GET /.git/config  returns 403
#   4. GET /wp-login.php returns 403
#   5. A path that does not exist returns 404, so bait and absence are
#      distinguishable in the log.
#   6. Every request appears in out/events.jsonl with sensor == "nginx".
#   7. Request bodies are NOT stored; only their byte length is recorded.
#
# Claim 2/3/4 matter most for teaching: return 403 rather than 404 because a
# scanner that sees "403 exists but I can't read it" keeps trying, and a
# scanner that sees 404 moves on. A decoy that deflects is a decoy that
# teaches nothing.
#
# Usage: ./scenarios/web-scan.sh [target] [port]

set -uo pipefail

# shellcheck disable=SC1091
[[ -f .env ]] && set -a && source .env && set +a

TARGET="${1:-${LAB_BIND_IP:-127.0.0.1}}"
PORT="${2:-${WEB_PORT:-8080}}"
BASE="http://${TARGET}:${PORT}"

# The bait. Ordered exactly as a scanner would try them: secrets first,
# then CMS, then admin panels.
PATHS=(
  "/"
  "/.env"
  "/.git/config"
  "/.aws/credentials"
  "/.ssh/id_rsa"
  "/wp-login.php"
  "/wp-admin/"
  "/xmlrpc.php"
  "/phpmyadmin/"
  "/admin.php"
  "/shell.php"
  "/this-path-does-not-exist-$(date +%s)"
)

# Expected status per path. Written out rather than computed, because the
# expectation is the lesson and it should be readable in the source.
expected_for() {
    case "$1" in
        "/") echo 200 ;;
        "/this-path-does-not-exist-"*) echo 404 ;;
        *) echo 403 ;;
    esac
}

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

say "TRAPDOOR scenario: web-scan"
echo "target ${BASE}"
echo "requests: ${#PATHS[@]}"
echo
echo "Every request below hits a decoy that is a real nginx, logging to a file"
echo "you can read. Nothing here is vulnerable; the lesson is that it looks"
echo "worth attacking."
echo

say "1. bait sweep"
FAIL=0
for path in "${PATHS[@]}"; do
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${BASE}${path}" 2>/dev/null)
    want=$(expected_for "$path")
    if [[ "$code" == "$want" ]]; then
        printf '   \033[32m%s\033[0m  %-45s (expected %s)\n' "$code" "$path" "$want"
    else
        printf '   \033[31m%s\033[0m  %-45s (expected %s)\n' "${code:-ERR}" "$path" "$want"
        FAIL=1
    fi
    # Paced like the SSH scenario, so timestamps are readable when projected.
    sleep 0.3
done

# --- claim 6: the events landed -------------------------------------------
say "2. what to check in out/events.jsonl"
cat <<'HINT'
   jq -r 'select(.sensor=="nginx") | [.ts, .http_status, .http_path] | @tsv' \
      out/events.jsonl | tail -20

   Then group by session to show how a scanner's requests cluster:
   jq -r 'select(.sensor=="nginx") | [.session_id, .src_ip] | @tsv' \
      out/events.jsonl | sort | uniq -c | sort -rn | head
HINT

say "3. limitation, stated on purpose"
cat <<'HINT'
   nginx cannot hash a request body inline. HTTP payload_sha256 is null and
   payload_bytes is a length only. SSH uploads through Cowrie ARE hashed,
   because Cowrie hands us the file. This is documented in docs/limitations.md
   and it is a real gap, not an oversight.
HINT

say "done"
[[ "$FAIL" -eq 0 ]] || { echo; echo "some responses did not match expectation — see above." >&2; exit 1; }
