#!/usr/bin/env bash
# TRAPDOOR — post-startup verification.
#
# Run this as the FIRST thing after `docker compose up -d`. Every check here
# exists because of a specific way this deployment can look fine and be wrong.
#
# The one that matters most: if LAB_BIND_IP is unset or wrong, Docker publishes
# the decoy ports on 0.0.0.0 and the whole lab is open to every network the host
# can see. No firewall rule saves you from that, because Docker writes its own
# rules ahead of yours. The only defence is looking.

set -uo pipefail

FAIL=0
ok()   { printf '  \033[32mOK\033[0m    %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=1; }
warn() { printf '  \033[33mWARN\033[0m  %s\n' "$1"; }
# "NOT RUN" is its own severity, and it fails the run. A pipeline that goes
# green with a check skipped is the same lie as a check reporting PASS on an
# exception — just one layer up. (Rule from Vera, 2026-11-01.)
skip() { printf '  \033[35mNOT RUN\033[0m  %s\n' "$1"; FAIL=1; }

cd "$(dirname "$0")/.." || exit 1

# shellcheck disable=SC1091
[[ -f .env ]] && set -a && source .env && set +a

LAB_BIND_IP="${LAB_BIND_IP:-}"
COWRIE_SSH_PORT="${COWRIE_SSH_PORT:-2222}"
COWRIE_TELNET_PORT="${COWRIE_TELNET_PORT:-2223}"
WEB_PORT="${WEB_PORT:-8080}"

echo "TRAPDOOR verification"
echo

# --- 1. the bind address ---------------------------------------------------
echo "1. port binding (the check that matters most)"

if [[ -z "$LAB_BIND_IP" ]]; then
    bad "LAB_BIND_IP is not set in .env — ports will publish on 0.0.0.0"
else
    ok "LAB_BIND_IP=${LAB_BIND_IP}"
fi

# A snapshot of every listening socket, taken now and diffed against the
# pre-startup snapshot when one exists. Check 1 above proves the decoy ports
# are bound where we think. This proves nothing ELSE opened while we worked.
# Those are different claims, and only one of them is made by looking at a
# single port.
mkdir -p .verify
CURRENT=".verify/ss-$(date -u +%Y%m%dT%H%M%SZ).txt"
ss -tlnp > "$CURRENT" 2>/dev/null || true
PREV=$(ls -1t .verify/ss-*.txt 2>/dev/null | sed -n 2p)

if [[ -n "$PREV" ]]; then
    if diff -q <(awk '{print $1, $4}' "$PREV") <(awk '{print $1, $4}' "$CURRENT") >/dev/null 2>&1; then
        ok "listening set unchanged since $(basename "$PREV")"
    else
        warn "listening set CHANGED since $(basename "$PREV"):"
        diff <(awk '{print $1, $4}' "$PREV") <(awk '{print $1, $4}' "$CURRENT") \
            | grep -E '^[<>]' | sed 's/^/          /'
    fi
else
    warn "no earlier snapshot to diff against — this run is the baseline"
fi

# Explicit wildcard look. "Listening" and "listening on the right interface"
# are different facts; this is the one that is unsafe.
wild=$(ss -tlnH 2>/dev/null | awk '{print $4}' | grep -E '^(\*|0\.0\.0\.0|\[::\]):' || true)
if [[ -n "$wild" ]]; then
    warn "something is bound to all interfaces:"
    echo "$wild" | sed 's/^/          /'
    # Ports we published ourselves are a hard failure; others are a note.
    for port in "$COWRIE_SSH_PORT" "$COWRIE_TELNET_PORT" "$WEB_PORT"; do
        echo "$wild" | grep -qE ":${port}$" && bad "published port ${port} is on ALL interfaces"
    done
else
    ok "nothing bound to a wildcard address"
fi

# ss output for a specific port. Looking for the bind address explicitly,
# because "0.0.0.0:8080" and "192.168.111.45:8080" both mean "listening".
for port in "$COWRIE_SSH_PORT" "$COWRIE_TELNET_PORT" "$WEB_PORT"; do
    line=$(ss -tlnH "sport = :${port}" 2>/dev/null | head -1)
    if [[ -z "$line" ]]; then
        bad "port ${port} is not listening at all"
    elif echo "$line" | grep -qE '(^|[[:space:]])(\*|0\.0\.0\.0|\[::\]):'"${port}"; then
        bad "port ${port} is bound to ALL interfaces — expected ${LAB_BIND_IP}"
    elif echo "$line" | grep -q "${LAB_BIND_IP}:${port}"; then
        ok "port ${port} bound to ${LAB_BIND_IP}"
    else
        warn "port ${port} bound somewhere unexpected: ${line}"
    fi
done

# --- 2. the decoy answers --------------------------------------------------
echo
echo "2. decoy reachable"

code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
        "http://${LAB_BIND_IP:-127.0.0.1}:${WEB_PORT}/" 2>/dev/null)
[[ "$code" == "200" ]] && ok "GET / -> 200" || bad "GET / -> ${code:-no response} (expected 200)"

code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
        "http://${LAB_BIND_IP:-127.0.0.1}:${WEB_PORT}/.env" 2>/dev/null)
# 403 is the design: "exists but forbidden" keeps a scanner engaged.
[[ "$code" == "403" ]] && ok "GET /.env -> 403 (bait path working)" \
                       || bad "GET /.env -> ${code:-no response} (expected 403)"

# --- 3. cowrie is pretending ----------------------------------------------
echo
echo "3. cowrie emulating ssh"

banner=$(timeout 5 nc "${LAB_BIND_IP:-127.0.0.1}" "$COWRIE_SSH_PORT" </dev/null 2>/dev/null | head -1)
if [[ "$banner" == SSH-2.0-* ]]; then
    ok "SSH banner: ${banner}"
else
    bad "no SSH banner on port ${COWRIE_SSH_PORT}"
fi

# --- 4. events landing -----------------------------------------------------
echo
echo "4. pipeline producing events"

if [[ ! -s out/events.jsonl ]]; then
    skip "event pipeline — out/events.jsonl is empty, nothing has proven it works"
else
    total=$(wc -l < out/events.jsonl)
    sensors=$(jq -r '.sensor' out/events.jsonl 2>/dev/null | sort -u | tr '\n' ' ')
    ok "${total} events, sensors seen: ${sensors}"
    # A schema drift would show up here as unparseable lines.
    badlines=$(jq -c . out/events.jsonl 2>/dev/null | grep -c . || echo 0)
    [[ "$badlines" == "$total" ]] || bad "some lines are not valid JSON (${badlines}/${total})"
fi

# C7 as a platform check rather than only a scenario claim. This is the one
# that fails quietly during a class: nginx serves the 403, logs it, and the
# normalizer throws the verdict away. The lab would then teach that a scanner
# hit /.env without ever saying what happened to it.
if [[ -s out/events.jsonl ]]; then
    if jq -e 'select(.sensor=="nginx")' out/events.jsonl >/dev/null 2>&1; then
        n_total=$(jq -s '[.[] | select(.sensor=="nginx")] | length' out/events.jsonl 2>/dev/null || echo 0)
        n_missing=$(jq -s '[.[] | select(.sensor=="nginx" and .http_status==null)] | length' out/events.jsonl 2>/dev/null || echo 0)
        if [[ "${n_missing:-0}" -eq 0 && "${n_total:-0}" -gt 0 ]]; then
            ok "every nginx event carries its status (${n_total} events)"
        else
            skip "nginx status missing on ${n_missing} of ${n_total} — the verdict is being dropped (C7)"
        fi
    fi
fi

# The decoy can answer perfectly while the log it writes is unparseable, and
# then every downstream check passes on an empty file. Parse the raw log
# directly, before the shipper has had a chance to hide the problem by
# dropping lines it could not read.
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 \
        && docker inspect trapdoor-web >/dev/null 2>&1; then
    raw_vol=$(docker volume inspect trapdoor_nginx_logs --format '{{.Mountpoint}}' 2>/dev/null)
    raw_log="${raw_vol}/trapdoor.json"
    if [[ -f "${raw_log}" ]]; then
        total=$(wc -l < "${raw_log}")
        # Parse with python3, NOT jq. jq is not installed on the target box and
        # "jq missing" counted as "0 valid lines", which reads exactly like a
        # broken log format. A check that cannot succeed is not a check, and
        # "tool absent" must never be reported as "thing broken".
        if command -v python3 >/dev/null 2>&1; then
            good=$(python3 -c '
import json, sys
n = 0
with open(sys.argv[1], "r", errors="replace") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            json.loads(line)
            n += 1
        except Exception:
            pass
print(n)
' "${raw_log}" 2>/dev/null || echo "PARSE_FAILED")
        else
            good="NO_PARSER"
        fi
        if [[ "${good}" == "NO_PARSER" || "${good}" == "PARSE_FAILED" ]]; then
            skip "cannot check the log format — no working parser on this host (C8 NOT RUN)"
            good=-1
        fi
        if [[ "${good:-0}" -lt 0 ]]; then
            :   # already reported above
        elif [[ "${total:-0}" -eq 0 ]]; then
            skip "nginx raw log exists but is empty — nothing has been sent yet"
        elif [[ "${good}" -lt "${total}" ]]; then
            skip "nginx raw log is INVALID JSON on $((total-good)) of ${total} lines (C8)"
        else
            ok "nginx raw log is valid JSON on all ${total} lines"
        fi
    else
        skip "nginx raw log not found at ${raw_log} — cannot check the log format (C8)"
    fi
fi

# Published ports that are not actually published. This is the failure we hit
# on the first deployment and it is worth its own check because everything
# else passes: containers healthy, decoy answering on its container IP, and
# nothing reachable from outside. Docker will not publish a port from a
# container on an internal-only network and says nothing when it declines.
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    declared=$(docker compose config 2>/dev/null | grep -cE "^\s+published:" || echo 0)
    bound=$(ss -tln 2>/dev/null | grep -cE ":(${COWRIE_SSH_PORT:-2222}|${COWRIE_TELNET_PORT:-2223}|${WEB_PORT:-8080})\b" || echo 0)
    if [[ "${declared:-0}" -eq 0 ]]; then
        skip "port publication — compose declares no published ports at all"
    elif [[ "${bound:-0}" -eq 0 ]]; then
        skip "port publication — ${declared} ports declared, NONE listening (internal network eats them)"
    elif [[ "${bound:-0}" -lt "${declared:-0}" ]]; then
        skip "port publication — ${bound} of ${declared} declared ports are listening"
    else
        ok "all ${declared} declared ports are published and listening"
    fi
fi

# --- 5. containers ---------------------------------------------------------
echo
echo "5. containers"
if command -v docker >/dev/null 2>&1; then
    running=$(docker compose ps --status running --format '{{.Service}}' 2>/dev/null | sort | tr '\n' ' ')
    ok "running: ${running:-none}"
    for svc in cowrie web shipper; do
        docker compose ps --status running --format '{{.Service}}' 2>/dev/null \
            | grep -qx "$svc" || bad "${svc} is not running"
    done
else
    bad "docker is not installed"
fi

# --- 6. egress check -------------------------------------------------------
echo
echo "6. honeypot egress (should be impossible)"
if ! command -v docker >/dev/null 2>&1; then
    # A check that cannot run is not a check that passed. Saying "OK" here
    # would be the same lie as the FORWARD comment that ate its own variable.
    skip "egress check — docker is not installed"
elif ! docker compose ps --status running --format '{{.Service}}' 2>/dev/null | grep -qx cowrie; then
    skip "egress check — cowrie is not running"
elif docker compose exec -T cowrie sh -c 'timeout 3 wget -q -O- http://192.168.0.1 >/dev/null 2>&1' 2>/dev/null; then
    bad "cowrie reached the LAN — internal:true is not in effect"
else
    ok "cowrie cannot reach the LAN (internal network holding)"
fi

echo
if [[ "$FAIL" -eq 0 ]]; then
    echo "all checks passed."
    exit 0
else
    echo "SOME CHECKS FAILED — do not call this deployed."
    exit 1
fi
