#!/usr/bin/env bash
# TRAPDOOR — is the box running the code we think it is running?
#
# Exists because on 2026-11-02 the live box was found running a tree that was
# one commit behind main, with no .git at all — an rsync'd copy from the night
# before. verify.sh passed on it. verify.sh was telling the truth about that
# tree; nobody was checking whether that tree was the one we meant.
#
# Those are different questions:
#   verify.sh  — is this deployment correct?
#   drift-check — is this deployment the one in the repo?
#
# A deployment can be perfectly correct and still be drift. Origin reading is
# not a security property, it is a provenance one, and it rots silently.

set -uo pipefail

FAIL=0
ok()   { printf '  \033[32mOK\033[0m    %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=1; }
warn() { printf '  \033[33mWARN\033[0m  %s\n' "$1"; }
skip() { printf '  \033[35mNOT RUN\033[0m  %s\n' "$1"; FAIL=1; }

cd "$(dirname "$0")/.." || exit 1

BRANCH="${TRAPDOOR_BRANCH:-main}"
echo "TRAPDOOR drift check"
echo

# --- 1. is this even a git checkout? ---------------------------------------
echo "1. provenance"
if [[ ! -d .git ]]; then
    bad "not a git checkout — this tree has no origin and cannot be compared to one"
    echo
    echo "SOME CHECKS FAILED — do not treat this deployment as tracked."
    exit 1
fi
ok "git checkout present"

# --- 2. is the working tree modified? --------------------------------------
echo
echo "2. working tree"
if ! git rev-parse --verify -q HEAD >/dev/null; then
    bad "HEAD does not resolve — repository exists but has no commits"
else
    # .git-creds and out/ are expected untracked/dirty; only tracked changes
    # count as drift.
    if [[ -z "$(git status --porcelain --untracked-files=no)" ]]; then
        ok "no uncommitted changes to tracked files"
    else
        bad "tracked files are modified in place — this box has drifted from any commit"
        git status --short --untracked-files=no | sed 's/^/          /' | head -10
    fi
fi

# --- 3. local HEAD vs origin -------------------------------------------------
echo
echo "3. HEAD vs origin/${BRANCH}"
if ! git remote get-url origin >/dev/null 2>&1; then
    bad "no origin remote configured — cannot tell what this should be"
else
    # Fetch quietly. A failure here must NOT read as "up to date": that is the
    # exact bug this repo has now shipped three times.
    if ! git fetch -q origin "$BRANCH" 2>/dev/null; then
        skip "could not fetch origin/${BRANCH} — network or credentials, NOT a verdict"
    else
        LOCAL=$(git rev-parse HEAD 2>/dev/null || echo "")
        REMOTE=$(git rev-parse "origin/${BRANCH}" 2>/dev/null || echo "")

        # Why there is no "is the ref stale?" check here, tried and removed on
        # 2026-11-07:
        #
        # June proposed refusing to report when the last fetch is old. Sound
        # instinct, but the fetch three lines above runs on every invocation, so
        # a FETCH_HEAD age test measures the fetch that just happened and can
        # never fail. It was written, it was proved tautological by freezing
        # FETCH_HEAD and watching it pass anyway, and it was removed.
        #
        # The real question is not "how old is the ref" but "did the fetch reach
        # the remote" -- and that is already handled: a failed fetch leaves
        # FETCH_HEAD untouched (verified against an unreachable host, mtime
        # unchanged), and the `if ! git fetch` above turns that into skip/NOT RUN.
        #
        # The 2026-11-07 incident was not a stale ref in this script. This script
        # always fetched. The stale ref was in `git status`, which nobody had run
        # fetch behind. That is why the box's own report said "1 behind" and the
        # truth was 9. The fix for that is this script existing and being the
        # thing that reports drift -- not another age gate on top of it.
        if [[ -z "$LOCAL" || -z "$REMOTE" ]]; then
            skip "could not resolve both revisions, NOT a verdict"
        elif [[ "$LOCAL" == "$REMOTE" ]]; then
            ok "HEAD is origin/${BRANCH} ($(git rev-parse --short HEAD))"
        else
            BEHIND=$(git rev-list --count "HEAD..origin/${BRANCH}" 2>/dev/null || echo "?")
            AHEAD=$(git rev-list --count "origin/${BRANCH}..HEAD" 2>/dev/null || echo "?")
            if [[ "$BEHIND" == "0" && "$AHEAD" != "0" ]]; then
                bad "local is ${AHEAD} commit(s) AHEAD of origin — unpushed work lives only on this box"
            elif [[ "$AHEAD" == "0" ]]; then
                bad "local is ${BEHIND} commit(s) BEHIND origin — the box is running old code"
            else
                bad "diverged: ${AHEAD} ahead, ${BEHIND} behind origin/${BRANCH}"
            fi
            echo "          local  $(git rev-parse --short HEAD) $(git log -1 --format=%s)"
            echo "          origin $(git rev-parse --short "origin/${BRANCH}") $(git log -1 --format=%s "origin/${BRANCH}")"
        fi
    fi
fi

# --- 4. uncommitted secrets sitting in the tree ------------------------------
echo
echo "4. untracked credential files"
# A credential file in the working tree is fine. A credential file that is NOT
# ignored is one `git add -A` away from being committed — which nearly happened
# on this box on 2026-11-02.
LEAKY=$(git status --porcelain --untracked-files=all 2>/dev/null | awk '$1=="??"{print $2}' \
        | grep -iE 'cred|secret|\.env$|passw|token|\.pem$|id_rsa' || true)
if [[ -z "$LEAKY" ]]; then
    ok "no untracked and un-ignored credential-looking files"
else
    bad "untracked files that look like credentials and are NOT gitignored:"
    printf '%s\n' "$LEAKY" | sed 's/^/          /'
fi

echo
if [[ "$FAIL" -eq 0 ]]; then
    echo "no drift — this box is running a tracked commit that matches origin."
    exit 0
else
    echo "DRIFT DETECTED — the running code is not the code in the repo."
    exit 1
fi
