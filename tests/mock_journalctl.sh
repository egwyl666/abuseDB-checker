#!/usr/bin/env bash
# Fake journalctl: 20 lines of service log, one of which leaks a secret.
echo "$*" >> "$MOCK_LOG/journalctl.log"
for i in $(seq 1 19); do echo "2026-10-15T06:00:$(printf %02d "$i")+0000 vps abuse-checker[42]: line $i"; done
echo "2026-10-15T06:00:20+0000 vps abuse-checker[42]: curl: (7) failed to connect to api.telegram.org/bot${MOCK_LEAK_TOKEN:-none}/sendMessage"
