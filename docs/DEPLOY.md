# Deploying TRAPDOOR

Target: an LXC on the lab network. This document assumes nothing about the
host beyond "it can run Docker."

## Container spec (as built by Vera, 2026-11-01)

```
name:        test-trapdoor
address:     192.168.111.45/16
gateway:     192.168.0.1
cores:       2
memory:      4096 MB
disk:        40 G
type:        unprivileged
startup:     onboot
```

| Field | Value |
|---|---|
| `LAB_CIDR` | `192.168.0.0/16` |
| `LAB_BIND_IP` | `192.168.111.45` |

> **Verify the gateway before anything else.** With a /16, `192.168.0.1` is
> numerically local to `192.168.111.45` — but "numeric neighbor" and "reachable
> next hop" are not the same thing if 111.x and 0.x sit on different VLANs.
> Check `ip route` and `ping 192.168.0.1` before running apt.

## Step 1 — base system

```bash
apt update && apt upgrade -y
apt install -y curl git ca-certificates jq net-tools tcpdump make
```

`make` is not decoration: every command in Steps 4 and 5 is a make target, so
without it the next thing you type fails with `make: command not found` and you
have installed nothing. Jim hit exactly this on 2026-11-18 and could not run a
single documented command until he installed it by hand.

`tcpdump` and `jq` are not optional for a lab box. Students will want to watch
the wire and read normalized events.

## Step 2 — Docker

```bash
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
docker compose version    # must be v2
```

## Step 3 — the repo

```bash
git clone https://github.com/crperdue73/Trapdoor.git /opt/trapdoor
cd /opt/trapdoor
cp .env.example .env
```

Edit `.env`:

```bash
SENSOR_HOSTNAME=web01
SENSOR_NAME=lab-sensor-01
LAB_BIND_IP=192.168.111.45
LAB_CIDR=192.168.0.0/16   # THIS FARM. A different lab uses its own range:
                          # .env.example ships 10.20.30.0/24 as a placeholder.
                          # Whatever you put here must be the network your
                          # students' traffic actually comes from.
COWRIE_SSH_PORT=2222
COWRIE_TELNET_PORT=2223
WEB_PORT=8080
RETENTION_DAYS=14

# The console. 8081 is the default; it is listed here so the Step 3 block and
# the console subsection below do not disagree about what exists.
CONSOLE_PORT=8081

# WHO MAY READ THE CONSOLE. NOT optional, and not the same as LAB_CIDR.
# Leave this out and Step 4's own command refuses to run.
ADMIN_CIDR=192.168.111.0/24
```

### The console, and the one line you must write yourself

The console is a read-only human view on port 8081: who is attacking, what they
typed, what they tried. It is on its own port because it is the one thing in
this stack that shows you real student keystrokes, and that is the one thing
that must not be readable by the people being taught.

Two variables, and they are different questions:

```bash
CONSOLE_PORT=8081

# Who may READ the console. Deliberately not the same as LAB_CIDR: the decoy is
# meant to be reachable by the lab, the console is not.
ADMIN_CIDR=192.168.111.0/24

# Who is on that network, in writing, for a human to read.
# QUOTE THE VALUE. verify.sh loads this file with `source`, so an unquoted `|`
# is a shell pipe and will eat the value.
CONSOLE_NETWORK_DECLARED='192.168.111.0/24|the two instructors, no students'
```

`verify.sh` check 8 refuses to pass while `CONSOLE_NETWORK_DECLARED` is empty.
That is not a formality. On a single-network farm the check cannot ask "is this
narrow enough", because there is nowhere narrower to go. It can ask whether a
human has written down who is allowed to read what students typed, and whether
the console agrees with that sentence. An undeclared scope is an unowned scope.

Two things worth knowing before you set them:

- `ADMIN_CIDR` narrower than this host's own network is refused by
  `firewall.sh`, by design. On a /24 box, a /24 is correct.
- `ADMIN_CIDR` **unset** is refused too, and that is the one people hit. It
  says `REFUSING: cannot determine the console host's own subnet`. The script
  can derive a scope from `LAB_BIND_IP`, but only when that address is actually
  on the box, so a `.env` copied from the example and edited in the wrong place
  lands here. Setting it is not optional and it is not a formality. (Jim filed
  this on 2026-11-18: the test suite is green on that state, because the tests
  measure whether the script tells the truth, not whether a stranger can run
  it. Those are two different questions and only one of them was automated.)
- The console binds to `LAB_BIND_IP` like everything else here. If
  `LAB_BIND_IP` is `0.0.0.0` the console answers on every interface, and the
  `ADMIN_CIDR` firewall rule is then the only thing between a student and the
  keystroke log. Set `LAB_BIND_IP` to the lab-facing address.

## Step 4 — bring it up

**Read this before you run it.** `make up` starts containers. It does not apply
the firewall, and the firewall is what keeps the console private. So between
this step and the next one, the console on port 8081 is bound to `LAB_BIND_IP`
with no firewall rule in front of it, and it has no password of its own. It
shows the keystroke log: usernames, passwords and commands that students typed
into the decoy.

Measured on a bench on 2026-11-18 with the documented defaults
(`LAB_BIND_IP=0.0.0.0`, `ADMIN_CIDR` unset): from a different host,
`curl http://<lab>:8081/api/events` returned **200, unauthenticated**, and the
body contained recorded credentials and commands. No token, no header.

That is a short window on a lab network and a long one on a lab network that
someone else can reach. Close it before you walk away:

```bash
make up              # or: docker compose up -d
sudo ./scripts/firewall.sh --apply    # until this runs, 8081 is open
docker compose ps
docker compose logs -f shipper
```

Expected: `firstboot` runs once and exits 0, `trapdoor-web`, `trapdoor-cowrie`
and `trapdoor-shipper` stay up.

Two things worth knowing about that firewall line:

- It needs root, which is why it is not inside `make up`. A `make up` that
  silently asks for sudo is a surprise nobody wants at 2am.
- With `ADMIN_CIDR` unset it scopes the console to this host's own subnet as the
  host defines it, which on a flat farm is the whole farm. Set `ADMIN_CIDR` in
  Step 3 if that is not what you want. If the derivation cannot resolve at all
  it refuses instead of scoping to nothing.

Do not reach for `LAB_BIND_IP=127.0.0.1` as a shortcut here. It binds the
console, but it also binds the decoy, so students cannot reach the thing they
are supposed to attack. The console and the decoy share one bind address
because they share one lab network. The firewall is the part that separates
them, and that is why it is not optional.

## Step 5 — confirm it actually works

This is the acceptance bar. All three must pass before the repo goes public.

```bash
# 1. The decoy answers
curl -sS -o /dev/null -w '%{http_code}\n' http://192.168.111.45:8080/
# expect 200

# 2. A bait path gets told to keep knocking
curl -sS -o /dev/null -w '%{http_code}\n' http://192.168.111.45:8080/.env
# expect 403

# 3. Cowrie is listening and pretending to be SSH
ssh -p 2222 -o StrictHostKeyChecking=no root@192.168.111.45
# expect a password prompt, not a connection refused

# 4. The events landed, normalized
jq -c . /opt/trapdoor/out/events.jsonl | tail -5
# expect: sensor=cowrie auth_failed, and sensor=nginx http_request
```

If step 4 shows `sensor: "nginx"` events with `http_path: "/.env"`, the whole
pipeline is working end to end.

## Disk {#disk}

RAM is the number people ask about and disk is the number that bites them.
Measured on `test-trapdoor` (2026-11-02), with the core stack up and idle,
`out/events.jsonl` empty:

```
du -sh .verify out   ->   48K  .verify     4.0K  out
df -h /              ->   40G total, 13G used, 25G free
```

The stack itself is small. The growth is all in two places, and only one of
them is pruned:

| What | Where | Grows? | Pruned by |
|---|---|---|---|
| Normalized events | `out/events.jsonl` | ~10–50 MB/day of class use | `RETENTION_DAYS` (whole files only) and `make clean` |
| Uploaded artifacts | `cowrie_var` Docker volume | only when a scenario uploads | `make clean` (`down -v`); **not** by retention |
| Container stdout logs | Docker `json-file` | capped at 10 MB × 3 per container | automatic rotation |
| Verification artifacts | `.verify/*.txt` | a few small files/day | nothing — delete by hand |

Budget **~10 GB free** for a laptop or a small LXC. That is `make clean`
steady state plus headroom, not a hard limit. Two things to know before a
semester-long run:

1. **Retention cannot prune the file it is writing.** `shipper.prune()` only
   unlinks `out/*.jsonl` whose mtime is older than the cutoff, and
   `events.jsonl` is appended to continuously, so its mtime is always now.
   The live file grows until you rotate it.
2. **The one-file log is the only thing retention sees.** Set `RETENTION_DAYS`
   to shorten the tail of *rotated* files; it will not shrink the active one.

Check before a class: `du -sh out/ .verify/ && docker system df`.

## Firewall

`make firewall` writes:

- **accept** from `LAB_CIDR` to the published ports
- **drop** everything else to those ports
- **no** rule ever forwards from the honeypot outward

## Known limitations at deploy time

Recorded honestly rather than discovered later. See `docs/limitations.md`.

- nginx cannot hash a request body inline; HTTP payloads are recorded by
  length only.
- Retention is a plain file-age prune, not index-aware.
- No dashboard yet. `out/events.jsonl` is the interface.

---

## Step 0 — record the auth.log baseline BEFORE you touch anything

Do this before `docker compose up`, before installing anything, before applying
any firewall rule. It takes ten seconds and it is the only record of what the
box looked like when it was handed over.

```bash
wc -l /var/log/auth.log
grep -oE 'from [0-9.]+' /var/log/auth.log | sort | uniq -c | sort -rn
last -a | head -20
ss -tlnp
date -u +%Y-%m-%dT%H:%M:%SZ
```

Write the output down somewhere outside this repo, with the timestamp. Do not
commit it — it contains source addresses.

**Measure the number fresh. Do not carry a number forward.** A baseline of
"76 lines" was true for one handoff and will be wrong for the next: every login
between handoff and your session adds to it, including the login you are using
right now. What carries forward is the **method** — the count, the source IPs,
the timestamp — not the value.

How to read the diff afterwards:

- **More lines than the baseline, same source IPs:** expected. People log in.
- **Same lines, different source IP:** not expected. Someone you did not
  account for has been on this box. Stop and find out who before continuing.
- **Fewer lines:** the log rotated. Anything above the current file count is
  invisible to you. Say so rather than assuming it was quiet.

## Step 0b — the handoff note from the box's builder

If someone else provisioned the container (Vera did, for VMID 189), get from
them: the line count, the source IPs seen, and the timestamp they measured at.
Their logins will be in the file and they are the only ones who can say so
truthfully. An unexplained source IP and an explained source IP look identical
in a log.

For the 189 handoff the record was: **76 lines at 22:45:32Z, all originating
192.168.111.42 (the engineering host), six sessions 22:37:58–22:45:32, zero
failed attempts.** Treat that as a worked example of the format, not as a
constant to reuse.

