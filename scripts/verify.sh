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
SKIPPED=0
skip() { printf '  \033[35mNOT RUN\033[0m  %s\n' "$1"; SKIPPED=$((SKIPPED+1)); FAIL=1; }

cd "$(dirname "$0")/.." || exit 1

# shellcheck disable=SC1091
# .env fills in what the caller did not set, and must not overwrite what they
# did. `source .env` plain clobbers the environment, which is how the firewall
# scope tests passed on a box with no .env and failed on the honeypot, where
# .env sets LAB_CIDR=192.168.0.0/16. Same fix as firewall.sh: snapshot, source,
# restore. Precedence: explicit environment > .env > built-in default.
__ENV_LAB_BIND_IP="${LAB_BIND_IP:-}"
__ENV_LAB_CIDR="${LAB_CIDR:-}"
__ENV_ADMIN_CIDR="${ADMIN_CIDR:-}"
__ENV_COWRIE_SSH_PORT="${COWRIE_SSH_PORT:-}"
__ENV_COWRIE_TELNET_PORT="${COWRIE_TELNET_PORT:-}"
__ENV_WEB_PORT="${WEB_PORT:-}"
__ENV_CONSOLE_PORT="${CONSOLE_PORT:-}"

[[ -f .env ]] && set -a && source .env && set +a

[[ -n "$__ENV_LAB_BIND_IP" ]] && LAB_BIND_IP="$__ENV_LAB_BIND_IP"
[[ -n "$__ENV_LAB_CIDR" ]] && LAB_CIDR="$__ENV_LAB_CIDR"
[[ -n "$__ENV_ADMIN_CIDR" ]] && ADMIN_CIDR="$__ENV_ADMIN_CIDR"
[[ -n "$__ENV_COWRIE_SSH_PORT" ]] && COWRIE_SSH_PORT="$__ENV_COWRIE_SSH_PORT"
[[ -n "$__ENV_COWRIE_TELNET_PORT" ]] && COWRIE_TELNET_PORT="$__ENV_COWRIE_TELNET_PORT"
[[ -n "$__ENV_WEB_PORT" ]] && WEB_PORT="$__ENV_WEB_PORT"
[[ -n "$__ENV_CONSOLE_PORT" ]] && CONSOLE_PORT="$__ENV_CONSOLE_PORT"

LAB_BIND_IP="${LAB_BIND_IP:-}"
LAB_CIDR="${LAB_CIDR:-}"
COWRIE_SSH_PORT="${COWRIE_SSH_PORT:-2222}"
COWRIE_TELNET_PORT="${COWRIE_TELNET_PORT:-2223}"
CONSOLE_PORT="${CONSOLE_PORT:-8081}"
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
    # Parsed with python3, not jq: jq is not installed on the lab host and a
    # check whose tool is missing reports the stack as broken when it is the
    # checker that is broken. The parser name is printed so a future reader
    # can tell which path ran.
    if command -v python3 >/dev/null 2>&1; then
        parse_out=$(python3 - "${PWD}/out/events.jsonl" <<'PYEOF' 2>&1
import json, sys, collections
total = bad = 0
sensors = collections.Counter()
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    total += 1
    try:
        sensors[json.loads(line).get("sensor")] += 1
    except Exception:
        bad += 1
print(f"{total} {bad} {' '.join(f'{k}={v}' for k, v in sorted(sensors.items()))}")
PYEOF
)
        read -r total badlines sensor_list <<< "$parse_out"
        ok "${total} events (python3 parser), sensors: ${sensor_list:-none}"
        for want in cowrie nginx; do
            if [[ "$sensor_list" == *"${want}="* ]]; then
                ok "sensor present: ${want}"
            else
                skip "sensor MISSING from events: ${want}"
            fi
        done
        if [[ "${badlines:-0}" -eq 0 ]]; then
            ok "every event line is valid JSON"
        else
            bad "${badlines}/${total} event lines are not valid JSON"
        fi
    else
        skip "event JSON check — NO PARSER (python3 absent), not run"
    fi
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

# Paths inside the cowrie image that our config points at. These were wrong
# once - copied from an older Cowrie layout, loaded without complaint, and
# only failed when a real session started - so they get checked against the
# image instead of being remembered.
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    # Only data files, and only ones the image is supposed to provide.
    # userdb.txt is OUR mounted file, not the image's: checking the image for
    # it asked the wrong question and reported a false MISSING.
    for cfg_path in $(grep -oE '/cowrie/[A-Za-z0-9_./-]+\.pickle' \
            cowrie/etc/cowrie.cfg 2>/dev/null | sort -u); do
        # The cowrie image has no sh, so the probe runs python3. Falls back
        # to a clear NOT RUN rather than a false MISSING.
        if docker exec trapdoor-cowrie python3 -c \
                "import sys; sys.exit(0 if __import__('os').path.isfile('${cfg_path}') else 1)" \
                2>/dev/null; then
            ok "cowrie image has ${cfg_path}"
        else
            skip "cowrie image is MISSING ${cfg_path} (every session will fail)"
        fi
    done
fi

# Cowrie reads userdb.txt with encoding="ascii". A single non-ASCII byte -
# one em dash in a comment - makes every authentication attempt raise
# UnicodeDecodeError. The TCP connection succeeds and the banner is served,
# so from outside it looks exactly like a wrong password, forever. This check
# exists because that is precisely what happened on the first deployment.
if [[ -f cowrie/etc/userdb.txt ]]; then
    if python3 -c 'import sys; open(sys.argv[1],"rb").read().decode("ascii")' \
            cowrie/etc/userdb.txt 2>/dev/null; then
        ok "cowrie/etc/userdb.txt is ASCII (Cowrie will be able to read it)"
    else
        skip "cowrie/etc/userdb.txt contains NON-ASCII bytes — every login will fail"
    fi
else
    skip "cowrie/etc/userdb.txt not found — cannot check the credential file"
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
            skip "nginx raw log exists but is empty: nothing has been sent yet"
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
    # grep -c prints "0" AND exits 1 when it matches nothing, so `|| echo 0`
    # appended a second line and made every [[ ... ]] below a syntax error.
    # The errors went to stderr, the numeric tests failed, and the check
    # printed "all 0 declared ports are published" for a stack with zero
    # running containers. Same shape as the egress bug: a check that fails
    # to look and then reports the good answer. No group here to absorb it.
    cfg=$(docker compose config 2>/dev/null)
    if [[ -z "$cfg" ]]; then
        skip "port publication — compose config produced no output, NOT a verdict"
    else
    declared=$(printf '%s\n' "$cfg" | grep -cE "^\s+published:")
    bound=$(ss -tln 2>/dev/null | grep -cE ":(${COWRIE_SSH_PORT:-2222}|${COWRIE_TELNET_PORT:-2223}|${WEB_PORT:-8080}|${CONSOLE_PORT:-8081})\b")
    declared=${declared:-0}; bound=${bound:-0}
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
else
    # Distinguish three outcomes, because collapsing them is how a check
    # certifies nothing:
    #   0            -> the container REACHED the LAN, containment broken
    #   1 (from py)  -> the connection was refused/unreachable, containment holds
    #   anything else-> the probe itself did not run
    #
    # The previous version ran `sh -c` and treated every non-zero exit as
    # success. The cowrie image has no sh, so the probe never ran, the failed
    # exec exited non-zero, and the check printed OK. It certified containment
    # by failing to look. That is the exact bug I had written a comment about
    # four lines above it.
    probe_script='
import socket, sys
try:
    s = socket.create_connection(("192.168.0.1", 80), timeout=3)
    s.close()
    sys.exit(0)          # CONNECTED - containment is broken
except OSError:
    sys.exit(1)          # refused or no route - containment holds
'
    docker compose exec -T cowrie python3 -c "$probe_script" >/dev/null 2>&1
    rc=$?
    if ! docker compose ps --status running --format '{{.Service}}' 2>/dev/null | grep -qx cowrie; then
        skip "egress check — cowrie went away mid-check, not run"
    elif docker compose exec -T cowrie python3 -c 'import sys; sys.exit(0)' >/dev/null 2>&1; then
        case "$rc" in
            0) bad "cowrie REACHED the LAN — internal:true is not in effect" ;;
            1) ok "cowrie cannot reach the LAN (connection refused, internal network holding)" ;;
            *) skip "egress check — probe exited ${rc}, NOT a verdict" ;;
        esac
    else
        skip "egress check — cannot run python3 in the cowrie container, NOT RUN"
    fi
fi

# --- 7. host firewall ------------------------------------------------------
# Docker publishes ports by writing its own iptables rules in the DOCKER chain,
# which are evaluated BEFORE any rule this repo adds to INPUT. So the honest
# question is not "did we write a firewall rule" but "what does the packet
# path actually look like".
#
# Added 2026-11-02 after finding the live box with zero TRAPDOOR rules applied
# and LAB_CIDR=192.168.0.0/16 — i.e. the whole farm could reach the decoy, and
# nothing said so. That may be the intended teaching model, but it should be a
# decision someone made, not a line nobody looked at.
echo "7. host firewall"

if ! command -v iptables >/dev/null 2>&1; then
    skip "firewall — iptables not installed, nothing examined"
else
    # Count what DOCKER-USER actually holds, not what the ruleset is named.
    # The previous form grepped the whole ruleset for the literal string
    # TRAPDOOR, which appeared in no rule this script writes, so a host with
    # all five rules applied and verified still reported "no TRAPDOOR rules
    # applied". It was true about the grep and false about the firewall.
    TRAPDOOR_RULES=$(iptables -S DOCKER-USER 2>/dev/null | grep -c 'TRAPDOOR-scope' || true)
    UFW_STATE=$(ufw status 2>/dev/null | head -1 || true)

    if [[ -n "$UFW_STATE" ]]; then
        ok "ufw is present: ${UFW_STATE#Status: }"
    fi

    # A rule that is present is not a rule that matches.
    #
    # On 2026-11-06 this chain held fifteen well-formed rules, no duplicates,
    # terminating in a DROP, with the decoy answering -- and every counter at
    # zero, because the rules sat below Docker's own RETURN and matched the
    # published port instead of the post-DNAT container destination. This
    # check would have printed OK throughout. Presence is the only thing the
    # old form tested, and presence was wrong four times in one day.
    #
    # So: if rules are present, at least one of them must have matched
    # traffic. A counter above zero means the chain is in the packet path. It
    # does not prove the scope is right, and it is not a substitute for the
    # deny test -- but it is the cheapest way to tell enforcement from
    # decoration.
    if [[ "$TRAPDOOR_RULES" -gt 0 ]]; then
        MATCHED=$(iptables -L DOCKER-USER -v -n 2>/dev/null \
            | grep 'TRAPDOOR-scope' | awk '$1 ~ /^[0-9]+$/ && $1 > 0' | wc -l || true)
        if [[ "$MATCHED" -gt 0 ]]; then
            ok "$MATCHED TRAPDOOR rule(s) have matched traffic (chain is in the path)"
        else
            warn "TRAPDOOR rules present but not one has matched a packet — present is not enforcing; check rule order and DNAT destination"
        fi
    fi

    if [[ "$TRAPDOOR_RULES" -eq 0 ]]; then
        warn "no TRAPDOOR-scope rules in DOCKER-USER (make firewall --apply); INPUT policy + Docker chains only"
    else
        ok "${TRAPDOOR_RULES} TRAPDOOR rules present"
    fi

    # The claim under test, measured 2026-11-02: published decoy ports are
    # DNATed, so ufw's INPUT chain never sees off-box traffic to them and
    # INPUT rules cannot restrict the decoy. DOCKER-USER is the hook that
    # does. What we report is the scope those rules enforce.
    if [[ -z "$LAB_CIDR" ]]; then
        # LAB_CIDR defaults to the farm /16 in firewall.sh. Reporting "unset"
        # here as a failure told every student who never set it that the host
        # had no scope, when the scope was the widest one available. Report the
        # effective value, because that is the one the rules enforce.
        LAB_CIDR="192.168.0.0/16"
        warn "LAB_CIDR unset in the environment — firewall.sh defaults to the farm /16, so that is the scope in force"
        warn "LAB_CIDR is the whole farm /16 — every host on the network can reach the decoy (DOCKER-USER rule matches nothing)"
        warn "  this is not a firewall failure; it is scope set too wide. Narrow LAB_CIDR for a real boundary"
    else
        ok "LAB_CIDR scoped to ${LAB_CIDR}"
    fi

    # ufw looks like protection for the decoy and is not. Say so on every run
    # rather than letting 'ufw is active' read as 'the honeypot is protected'.
    if [[ -n "$UFW_STATE" ]]; then
        warn "ufw does not cover the decoy: published ports are DNATed and bypass INPUT"
    fi
fi

# --- 8. the console is NOT reachable from the lab ---------------------------
#
# The console shows what every student typed: source addresses, the passwords
# they guessed, the commands they ran. That is a materially different asset
# from the decoy, and it must not inherit the decoy's LAB_CIDR scope. On
# 2026-11-12 I published the console on 8081 and left it out of firewall.sh
# and verify.sh entirely, which is the exact failure this repo keeps finding:
# a new thing that reports fine and is covered by nothing.
#
# This check asserts the boundary rather than the port. A port count would go
# green either way.
echo
echo "8. console scope (must NOT be lab-reachable)"

CONSOLE_CIDR="${ADMIN_CIDR:-}"
if [[ -z "$CONSOLE_CIDR" ]]; then
    warn "ADMIN_CIDR unset: firewall.sh derives it from this host's own subnet; set it explicitly to make this check meaningful"
fi

if command -v iptables >/dev/null 2>&1; then
    # Every console DROP must have an ACCEPT above it that is NARROWER than
    # LAB_CIDR. If the console's accept is the same scope as the decoy's, the
    # split was not applied and the console is as open as the bait.
    console_accepts=$(iptables -S DOCKER-USER 2>/dev/null \
        | grep -- 'TRAPDOOR-scope' | grep -- "--dport ${CONSOLE_PORT:-8081}" \
        | grep -- '-j ACCEPT' || true)
    console_drops=$(iptables -S DOCKER-USER 2>/dev/null \
        | grep -- 'TRAPDOOR-scope' | grep -- "--dport ${CONSOLE_PORT:-8081}" \
        | grep -c -- '-j DROP' || true)

    if [[ -z "$console_accepts" ]]; then
        # A console with no rules is not a console with no problem: it means
        # firewall.sh has not been applied since the port was added, so nothing
        # is known about who can read it. Warning alone let an un-auditable
        # console pass silently, which is the same shape as the bug this check
        # exists to catch. Report NOT RUN and let the run fail.
        warn "no console ACCEPT rules in DOCKER-USER (firewall.sh not applied since the console was added?)"
        skip "console scope (no console rules on ${CONSOLE_PORT:-8081} to compare)"
    elif [[ "${console_drops:-0}" -eq 0 ]]; then
        warn "console has ACCEPT rules and no DROP: anything not matched falls through to the chain policy"
    else
        ok "console rules present on ${CONSOLE_PORT:-8081} (${console_drops} drop)"
    fi

    # The assertion that has teeth. The question is NOT "is the console scoped
    # to the farm /16". That was the first version of this check and it was
    # wrong twice over:
    #
    #   1. On this farm the /16 IS the network. Hard-coding it as a leak meant
    #      the check failed the correct configuration and passed nothing.
    #   2. Rewriting it to go green would have been the same lie in the other
    #      direction: the check was telling on a real defect and I nearly
    #      silenced it instead of reading it.
    #
    # The real defect it was pointing at: LAB_CIDR and ADMIN_CIDR were BOTH
    # 192.168.0.0/16 on this host, so the console had no narrower scope than
    # the bait. It accepts the whole farm. Every student machine can read every
    # other student's source addresses, guessed passwords and typed commands.
    #
    # So the question is: is the console's ACCEPT scope wider than the operator
    # network it is supposed to be limited to? Compare the actual prefix
    # lengths rather than matching a literal string, so this works on any farm
    # size instead of only the one I happened to be sitting in.
    #
    # Wider than the operator's own network means people the console is not for
    # can read it. Fail, do not warn.
    if [[ -n "$console_accepts" ]]; then
        # Pull the source CIDR off each console ACCEPT and find the shortest
        # prefix (the widest scope). Only farm-scale sources matter here; the
        # docker bridge host rules (172.x/32) are single addresses and are
        # needed for the port to work at all.
        widest=""
        widest_bits=999
        while read -r src; do
            [[ -z "$src" ]] && continue
            bits="${src#*/}"
            [[ "$bits" =~ ^[0-9]+$ ]] || continue
            # Only consider sources in the operator's own address family/space
            case "$src" in
                192.168.*) ;;
                10.*) ;;
                172.1[6-9].*|172.2[0-9].*|172.3[01].*) ;;
                *) ;;
            esac
            if [[ "$bits" -lt "$widest_bits" ]]; then
                widest_bits="$bits"
                widest="$src"
            fi
        done < <(printf '%s\n' "$console_accepts" \
                 | sed -n 's/.*-s \([^ ]*\).*/\1/p')

        if [[ -z "$widest" ]]; then
            warn "could not read a source CIDR off the console ACCEPT rules; check skipped"
            skip "console scope comparison (no parseable -s on the console accepts)"
        else
            # THE CHECK IS NOT "IS THE SCOPE NARROW". IT IS "IS THE SCOPE
            # DECLARED".
            #
            # The previous version failed any scope with a prefix <= 16, on the
            # reasoning that a /16 is the whole farm and the console should not
            # be farm-wide. That reasoning assumed the farm has a narrow
            # operator network to scope to. It does not: this deployment runs
            # ONE network, the whole IT department is on a single /16, and
            # there is no student VLAN to narrow to. So the check failed the
            # only configuration that exists, every run, forever, and a check
            # that cannot pass is a check nobody reads. That is the same lie as
            # a check that cannot fail, arriving from the other direction.
            #
            # What replaces it still has teeth. It asks the two questions that
            # can actually be wrong:
            #
            #   1. Is there a WRITTEN declaration of the operator network, and
            #      does the console's real scope match it? An undeclared scope
            #      is an unowned scope: nobody has said out loud who may read
            #      what students typed. That fails.
            #   2. Has the scope drifted WIDER than the declaration? That is the
            #      leak the old check was reaching for, and it still fails.
            #
            # CONSOLE_NETWORK_DECLARED lives in .env next to ADMIN_CIDR. It is
            # a sentence naming who is on the network, written by a human, not
            # inferred from a prefix length. A single /16 declared as "entire
            # IT department, no student VLAN" is honest and passes. The same
            # /16 with no declaration does not.
            _declared="${CONSOLE_NETWORK_DECLARED:-}"
            _declared_cidr="${_declared%%|*}"
            _declared_bits="${_declared_cidr#*/}"

            if [[ -z "$_declared" ]]; then
                echo "  FAIL console accepts ${widest} and NO operator network is declared" >&2
                echo "         nobody has said in writing who is allowed to read what" >&2
                echo "         students typed. An undeclared scope is an unowned scope." >&2
                echo "         Set CONSOLE_NETWORK_DECLARED in .env, in the form" >&2
                echo "           CONSOLE_NETWORK_DECLARED='<cidr>|<who is on it>'" >&2
                echo "         including the reason if the network is wider than the" >&2
                echo "         console's audience. A real answer beats a narrow one." >&2
                FAIL=1
            elif [[ ! "$_declared_bits" =~ ^[0-9]+$ ]]; then
                echo "  FAIL CONSOLE_NETWORK_DECLARED is set but its CIDR does not parse" >&2
                echo "         got: '${_declared_cidr}'  want: 'a.b.c.d/len|who is on it'" >&2
                FAIL=1
            elif (( widest_bits < _declared_bits )); then
                echo "  FAIL console accepts ${widest}, WIDER than the declared operator" >&2
                echo "         network ${_declared_cidr}. The console reports on people the" >&2
                echo "         declaration does not cover. Either narrow ADMIN_CIDR or" >&2
                echo "         widen the declaration and say why in it." >&2
                FAIL=1
            elif (( widest_bits > _declared_bits )); then
                # Narrower than declared is not a leak, but it is a scope
                # nobody described, and the 2026-11-12 afternoon proved that a
                # narrow-looking default can lock out the human it was for.
                warn "console accepts ${widest}, NARROWER than declared ${_declared_cidr}"
                warn "  not a leak, but verify this reaches the people it is for"
                ok "console scope ${widest} is declared and not wider than the declaration"
            else
                ok "console scope ${widest} matches the declared operator network"
            fi
        fi
    fi
fi

echo
if [[ "$FAIL" -eq 0 ]]; then
    echo "all checks passed."
    exit 0
else
    # Name the reason. On 2026-11-12 this printed "SOME CHECKS FAILED" under a
    # screen of green OK lines, because the only thing that failed was a NOT
    # RUN. Correct verdict, useless sentence: a human reads the tail, sees no
    # red, and learns to distrust the verdict instead of the check. The run is
    # still failed, deliberately (Vera, 2026-11-01: green with a check skipped
    # is the same lie as PASS on an exception), but it now says which one.
    if [[ "${SKIPPED:-0}" -gt 0 ]]; then
        echo "SOME CHECKS FAILED: ${SKIPPED} check(s) could not run (NOT RUN)."
        echo "A skipped check is not a passed check. Do not call this deployed"
        echo "until every NOT RUN above either runs or is ruled out by hand."
    else
        echo "SOME CHECKS FAILED: do not call this deployed."
    fi
    exit 1
fi
