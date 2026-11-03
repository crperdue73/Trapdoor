# TRAPDOOR
#
# Every target is meant to be readable by a student. If a recipe needs a
# comment to explain it, the recipe is doing too much.

SHELL := /bin/bash
COMPOSE := docker compose

# Scenario names are plain words passed as SCENARIO=<name>, not baked into
# target names. `scenario/ssh-bruteforce` worked, but a slash in a target is
# read as a path by anyone who has written a Makefile, it tab-completes badly,
# and `make help` could not list the scenarios it supported.
SCENARIOS := ssh-bruteforce web-scan nmap

.PHONY: help up down restart logs ps events sessions scenario firewall test \
        clean verify deploy drift health timer-install timer-remove

help:
	@echo "TRAPDOOR — internal honeypot lab"
	@echo
	@echo "  make up                      start cowrie + nginx + shipper"
	@echo "  make down                    stop everything (volumes kept)"
	@echo "  make logs                    follow shipper output"
	@echo "  make ps                      container status"
	@echo "  make events                  pretty-print normalized events"
	@echo "  make sessions                list sessions with event counts"
	@echo "  make sessions SESSION=<id>   render one session end to end"
	@echo "  make scenario SCENARIO=<n>   run a scripted attack. n ="
	@for s in $(SCENARIOS); do echo "                                 - $$s"; done
	@echo "  make firewall                print the iptables rules for review"
	@echo "  make verify                  run verify.sh (is this deployment correct?)"
	@echo "  make drift                   compare running tree to origin (is it the repo?)"
	@echo "  make health                  drift + verify, report to .verify/"
	@echo "  make deploy                  pull origin + rebuild + verify (idempotent)"
	@echo "  make timer-install           install systemd timer for make health"
	@echo "  make timer-remove            remove that timer"

up:
	$(COMPOSE) up -d --build
	@echo
	@echo "waiting for first events..."
	@sleep 3
	@$(MAKE) --no-print-directory ps
	@echo
	@$(MAKE) --no-print-directory verify

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

# No SESSION -> the index. With SESSION -> the transcript for that one
# session, in time order, which is the thing an instructor actually puts on
# a projector. Both read the same file so they can never disagree.
sessions:
	@test -f out/events.jsonl || { echo "no events yet — run a scenario first"; exit 0; }
	@if [ -z "$(SESSION)" ]; then \
	  printf '%-14s %-8s %6s  %s\n' session sensor events "first seen"; \
	  jq -r '[.session_id, .sensor, .ts] | @tsv' out/events.jsonl \
	    | sort \
	    | awk -F'\t' '{n[$$1 SUBSEP $$2]++; if (!(($$1 SUBSEP $$2) in f)) f[$$1 SUBSEP $$2]=$$3} \
	        END {for (k in n) {split(k,p,SUBSEP); print p[1]"\t"p[2]"\t"n[k]"\t"f[k]}}' \
	    | sort -k1,1 -k4,4r \
	    | awk -F'\t' '{printf "%-14s %-8s %6d  %s\n", $$1, $$2, $$3, $$4}'; \
	else \
	  python3 scripts/render_session.py out/events.jsonl "$(SESSION)"; \
	fi

# The scenario name is data, so it is also checked before it is executed:
# `make scenario SCENARIO=nmap; rm -rf /` must not be a way to run anything.
scenario:
	@test -n "$(SCENARIO)" || { echo "which one? SCENARIO=<name>"; \
	  for s in $(SCENARIOS); do echo "  $$s"; done; exit 1; }
	@case " $(SCENARIOS) " in \
	  *" $(SCENARIO) "*) ;; \
	  *) echo "unknown scenario: $(SCENARIO)"; \
	     echo "known: $(SCENARIOS)"; exit 1 ;; \
	esac
	@./scenarios/$(SCENARIO).sh

# Printed, never applied automatically. A honeypot that rewrites the host
# firewall on `make up` is a surprise nobody wants at 2am.
firewall:
	@./scripts/firewall.sh --print

test:
	@python3 tests/test_shipper.py

# --- verification ---------------------------------------------------------

verify:
	@bash scripts/verify.sh

drift:
	@bash scripts/drift-check.sh

health:
	@bash scripts/health-check.sh

# Pull, rebuild, verify. This exists because on 2026-11-02 the live box was
# found running a tree one commit behind main with no .git at all, and there
# was no command that would have caught it. `make deploy` is that command.
#
# It refuses to run on a dirty tree: pulling over uncommitted work loses
# edits silently, and "it worked on my box" is not a story I want to tell.
deploy:
	@test -d .git || { echo "not a git checkout — clone the repo first:"; \
	  echo "  git clone https://github.com/crperdue73/Trapdoor.git /opt/trapdoor"; exit 1; }
	@test -z "$$(git status --porcelain --untracked-files=no)" || { \
	  echo "refusing to deploy: tracked files are modified"; \
	  git status --short --untracked-files=no; exit 1; }
	git pull --ff-only
	$(COMPOSE) up -d --build
	@echo
	@$(MAKE) --no-print-directory drift
	@echo
	@$(MAKE) --no-print-directory verify

# --- scheduled health check ------------------------------------------------
# A lab that is correct only when somebody is looking is correct by accident.
# The timer runs scripts/health-check.sh every 15 minutes and the latest verdict
# lands in .verify/health-latest.txt.

timer-install:
	@install -m 644 scripts/trapdoor-health.service /etc/systemd/system/trapdoor-health.service
	@install -m 644 scripts/trapdoor-health.timer /etc/systemd/system/trapdoor-health.timer
	@systemctl daemon-reload
	@systemctl enable --now trapdoor-health.timer
	@echo "installed. next run:"
	@systemctl list-timers trapdoor-health.timer --no-pager | sed -n 2p

timer-remove:
	@systemctl disable --now trapdoor-health.timer 2>/dev/null || true
	@rm -f /etc/systemd/system/trapdoor-health.service /etc/systemd/system/trapdoor-health.timer
	@systemctl daemon-reload
	@echo "removed"

clean:
	$(COMPOSE) down -v
	rm -f out/*.jsonl
	@echo "collected data deleted"