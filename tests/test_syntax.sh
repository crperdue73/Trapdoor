#!/bin/bash
# tests/test_syntax.sh — every shell script in the tree must parse.
#
# Why this exists (G2 in docs/ACCEPTANCE.md):
#
# On 2026-11-02, scripts/firewall.sh contained a stray `fi` and three uses of
# $BRIDGES whose declaration had been deleted. The script that proves the
# honeypot is contained could not be parsed at all — so `firewall.sh --apply`
# could not run, and the containment claim in this repo rested on a code path
# that was not executable from the commit that made the claim.
#
# Nothing noticed for two days. Not `make test` (it never looked at shell), not
# `make verify` (it runs scripts, it does not read them), not code review (I
# wrote the edit that broke it and read it as correct). The one thing that
# found it was `bash -n`, run by hand, once.
#
# A check that has to be remembered is not a check in this repo. This is it,
# in `make test`, run before every push.
#
# What it does NOT prove: that a script is correct, or that it will work when
# run. Parsing is not running. This closes the "cannot be parsed" gap only.
#
# Exit non-zero on any script that fails to parse.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

# Every tracked .sh, plus any .sh in the tree not yet tracked. out/ and .git/
# hold generated and vendored content and are excluded by the -path filters.
mapfile -t scripts < <(find . \
    -name '*.sh' \
    -not -path './.git/*' \
    -not -path './out/*' \
    -not -path './node_modules/*' \
    | sort)

if [[ ${#scripts[@]} -eq 0 ]]; then
    echo "FAIL  no shell scripts found — the finder is broken, not the tree" >&2
    exit 1
fi

fail=0
for f in "${scripts[@]}"; do
    if err=$(bash -n "$f" 2>&1); then
        echo "PASS  $f"
    else
        # Report the parser's own words, not a summary of them. On 14c67d8
        # the message was "line 245: syntax error near unexpected token 'fi'"
        # and that line number was the whole diagnosis.
        echo "FAIL  $f" >&2
        echo "$err" | sed 's/^/      /' >&2
        fail=1
    fi
done

if [[ $fail -ne 0 ]]; then
    echo >&2
    echo "A script that cannot be parsed cannot disagree with you." >&2
    echo "It also cannot run — so every claim that depends on it is unproven." >&2
    exit 1
fi

echo "PASS  ${#scripts[@]} shell scripts parse (parsing is not running)"
