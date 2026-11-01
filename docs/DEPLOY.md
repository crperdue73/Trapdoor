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
apt install -y curl git ca-certificates jq net-tools tcpdump
```

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
LAB_CIDR=192.168.0.0/16
COWRIE_SSH_PORT=2222
COWRIE_TELNET_PORT=2223
WEB_PORT=8080
RETENTION_DAYS=14
```

## Step 4 — bring it up

```bash
make up          # or: docker compose up -d
docker compose ps
docker compose logs -f shipper
```

Expected: `firstboot` runs once and exits 0, `trapdoor-web`, `trapdoor-cowrie`
and `trapdoor-shipper` stay up.

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
