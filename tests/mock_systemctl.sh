#!/usr/bin/env bash
# Fake systemctl for the test suite: logs every call; unit health comes
# from MOCK_SC_* variables.
echo "$*" >> "$MOCK_LOG/systemctl.log"
case "$1" in
    is-failed) [[ -n "${MOCK_SC_FAILED:-}" ]] ;;
    is-active) [[ -z "${MOCK_SC_TIMER_INACTIVE:-}" ]] ;;
    is-enabled) [[ -z "${MOCK_SC_TIMER_DISABLED:-}" ]] ;;
    show) echo "Thu 2026-10-15 18:00:00 UTC" ;;
    *) exit 0 ;;
esac
