# TRAPDOOR
#
# Every target is meant to be readable by a student. If a recipe needs a
# comment to explain it, the recipe is doing too much.

SHELL := /bin/bash
COMPOSE := docker compose

.PHONY: help up down restart logs ps events sessions scenario/ssh-bruteforce \
        scenario/web-scan scenario/nmap firewall test clean

help:
	@echo "TRAPDOOR — internal honeypot lab"
	@echo
	@echo "  make up                      start cowrie + nginx + shipper"
	@echo "  make down                    stop everything (volumes kept)"
	@echo "  make logs                    follow shipper output"
	@echo "  make ps                      container status"
	@echo "  make events                  pretty-print normalized events"
	@echo "  make sessions                list sessions with event counts"
	@echo "  make scenario/ssh-bruteforce run the SSH brute-force lesson"
	@echo "  make scenario/web-scan       run the web scanner lesson"
	@echo "  make scenario/nmap           run the port sweep lesson"
	@echo "  make firewall                print the iptables rules for review"
	@echo "  make test                    run the normalizer test suite"
	@echo "  make clean                   stop and DELETE collected data"

up:
	$(COMPOSE) up -d --build
	@echo
	@echo "waiting for first events..."
	@sleep 3
	@$(MAKE) --no-print-directory ps

down:
	$(COMPOSE) down

restart: down up

logs:
	$(COMPOSE) logs -f shipper

ps:
	@$(COMPOSE) ps

events:
	@test -f out/events.jsonl || { echo "no events yet — run a scenario first"; exit 0; }
	@tail -n 40 out/events.jsonl | jq -c .

sessions:
	@test -f out/events.jsonl || { echo "no events yet — run a scenario first"; exit 0; }
	@echo "session        sensor   events  first seen"
	@jq -r '[.session_id, .sensor] | @tsv' out/events.jsonl 2>/dev/null \
	  | sort | uniq -c | sort -rn | head -20

scenario/ssh-bruteforce:
	@./scenarios/ssh-bruteforce.sh

scenario/web-scan:
	@./scenarios/web-scan.sh

scenario/nmap:
	@./scenarios/nmap.sh

# Printed, never applied automatically. A honeypot that rewrites the host
# firewall on `make up` is a surprise nobody wants at 2am.
firewall:
	@./scripts/firewall.sh --print

test:
	@python3 tests/test_shipper.py

clean:
	$(COMPOSE) down -v
	rm -f out/*.jsonl
	@echo "collected data deleted"
