#!/bin/bash
set -euo pipefail

LOG_DIR=/logs/verifier
REWARD_FILE="$LOG_DIR/reward.txt"
STATUS_FILE="$LOG_DIR/verification-status.txt"
TEST_LOG="$LOG_DIR/test-stdout.txt"
TRUSTED_PYTHON=/usr/local/bin/python3
TRUSTED_TIMEOUT=/usr/bin/timeout
completed=0
mkdir -p "$LOG_DIR"

write_reward() {
    local value="$1"
    chmod 0644 "$REWARD_FILE" 2>/dev/null || true
    printf '%s\n' "$value" > "$REWARD_FILE"
    chmod 0444 "$REWARD_FILE"
}

write_status() {
    chmod 0644 "$STATUS_FILE" 2>/dev/null || true
    printf '%s\n' "$1" > "$STATUS_FILE"
    chmod 0444 "$STATUS_FILE"
}

on_exit() {
    if [ "$completed" -ne 1 ]; then
        write_status "INCOMPLETE: verifier exited before pytest completion"
        write_reward 0.000
    fi
}

on_signal() {
    write_status "INCOMPLETE: verifier interrupted before pytest completion"
    write_reward 0.000
    completed=1
    exit 0
}

write_reward 0.000
write_status "INCOMPLETE: pytest has not completed"
trap on_exit EXIT
trap on_signal INT TERM HUP

REPORT=$(mktemp "$LOG_DIR/pytest-results.XXXXXX")
rm -f "$REPORT"

SITE_PACKAGES=$(env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp \
    "$TRUSTED_PYTHON" -I -S -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')

set +e
env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8 \
    "$TRUSTED_PYTHON" -m pip install --disable-pip-version-check --no-cache-dir \
    --no-index --find-links=/tests/wheels pytest==8.4.1 >/dev/null 2>&1
PIP_RC=$?
set -e
if [ "$PIP_RC" -ne 0 ]; then
    write_status "INCOMPLETE: trusted pytest dependency installation failed"
    write_reward 0.000
    completed=1
    rm -f "$REPORT"
    exit 0
fi

set +e
env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8 \
    PYTHONPATH="$SITE_PACKAGES:/tests" PYTHONNOUSERSITE=1 \
    PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
    "$TRUSTED_TIMEOUT" --signal=TERM --kill-after=10s 300s \
    "$TRUSTED_PYTHON" -S -s -P -B -c \
    'import sys, pytest; raise SystemExit(pytest.main(sys.argv[1:]))' \
    -v -p no:cacheprovider --junitxml="$REPORT" /tests/test_outputs.py > "$TEST_LOG" 2>&1
rc=$?
set -e
cat "$TEST_LOG" 2>/dev/null || true

if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
    case "$rc" in
        124|125|126|127|137|143)
            write_status "INCOMPLETE: pytest did not complete; runner exited with code $rc"
            ;;
        *)
            write_status "INCOMPLETE: pytest exited before a scoreable report with code $rc"
            ;;
    esac
    write_reward 0.000
elif [ ! -s "$REPORT" ]; then
    write_status "INCOMPLETE: pytest completion report missing"
    write_reward 0.000
elif [ "$rc" -eq 0 ]; then
    write_status "COMPLETED: all verifier tests passed"
    write_reward 1.000
else
    write_status "COMPLETED: one or more verifier tests failed"
    write_reward 0.000
fi
completed=1
rm -f "$REPORT"
exit 0
