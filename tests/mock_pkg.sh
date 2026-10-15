#!/usr/bin/env bash
# Fake package manager for the test suite: logs every call; an install
# "provides" every tool by emptying the fake-missing list.
echo "$*" >> "$MOCK_LOG/pkg.log"
[[ -n "${MOCK_PKG_FAIL:-}" ]] && { echo "E: Unable to locate package" >&2; exit 100; }
case " $* " in
    *" install "*|*" add "*|*" -S "*) [[ -n "${ABUSE_CHECKER_FAKE_MISSING_FILE:-}" ]] && : > "$ABUSE_CHECKER_FAKE_MISSING_FILE" ;;
esac
exit 0
