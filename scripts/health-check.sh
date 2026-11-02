#!/usr/bin/env bash
# TRAPDOOR — scheduled health check.
#
# Runs drift-check.sh then verify.sh, and writes a verdict somewhere a human
# will actually see it. Designed to be run from systemd timer or cron.
#
# The reason this exists: on 2026-11-02 the stack was green because a person
# ran verify.sh by hand and read it. Between runs, nothing looked. A lab that
# is only correct when someone is watching is correct by accident.
#
# Exit codes:
#   0  everything green
#   1  verify failed (deployment is wrong)
#   2  drift detected (deployment is not the repo)
#   3  could not run (NOT a pass — collapses to failure on purpose)

set -uo pipefail

cd "$(dirname "$0")/.." || exit 3

STATUS_DIR="${TRAPDOOR_STATUS_DIR:-.verify}"
mkdir -p "$STATUS_DIR"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
REPORT="${STATUS_DIR}/health-${STAMP}.txt"
LATEST="${STATUS_DIR}/health-latest.txt"

{
    echo "TRAPDOOR health check — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "host: $(hostname)  uptime: $(uptime -p 2>/dev/null || echo unknown)"
    echo
    echo "=== drift ==="
    bash scripts/drift-check.sh
    echo "drift_exit=$?"
    echo
    echo "=== verify ==="
    bash scripts/verify.sh
    echo "verify_exit=$?"
    echo
} > "$REPORT" 2>&1

true

# Make health reports easy to find without hunting for a timestamp.
# Only link reports that actually reached a verdict — a half-written report
# labelled "latest" is a way to read a truncated file as the current state.
if grep -qE '^verify_exit=[0-9]+$' "$REPORT" 2>/dev/null; then
    cp -f "$REPORT" "$LATEST"
else
    echo "WARNING: report is incomplete, not promoted to health-latest.txt" >&2
fi

# Keep 30 days of reports. Small files, but unbounded growth is still rot.
find "$STATUS_DIR" -name 'health-*.txt' ! -name 'health-latest.txt' -mtime +30 -delete 2>/dev/null || true

# Pull the exit codes back out of the report rather than trusting variables
# from a subshell — this is the mistake this repo has made three times, and I
# am not making it a fourth.
DRIFT_RC=$(sed -n 's/^drift_exit=\([0-9]*\).*/\1/p' "$REPORT" | tail -1)
VERIFY_RC=$(sed -n 's/.*verify_exit=\([0-9]*\)$/\1/p' "$REPORT" | tail -1)

if [[ -z "$DRIFT_RC" || -z "$VERIFY_RC" ]]; then
    echo "could not determine a verdict from the report — treating as failure"
    exit 3
fi

if [[ "$DRIFT_RC" -ne 0 ]]; then
    echo "DRIFT: running code does not match the repo. See $REPORT"
    exit 2
fi

if [[ "$VERIFY_RC" -ne 0 ]]; then
    echo "VERIFY FAILED. See $REPORT"
    exit 1
fi

echo "green. See $REPORT"
exit 0
