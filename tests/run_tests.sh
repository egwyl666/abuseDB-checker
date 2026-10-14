#!/usr/bin/env bash
# shellcheck disable=SC2016  # bash -c snippets use single quotes on purpose
# Self-contained test suite for abuse-checker. No network, no root needed.
# Usage: bash tests/run_tests.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
SCRIPT="$ROOT/abuse-checker.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ac-tests.XXXXXX")"
if [[ -n "${KEEP_WORK:-}" ]]; then echo "work dir: $WORK"; else trap 'rm -rf "$WORK"' EXIT; fi

PASS=0 FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [[ -n "${2:-}" ]] && printf '       %s\n' "$2"; }
check() { local d="$1"; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }
section() { printf '\n== %s\n' "$1"; }

# Dummy secrets: none of these may ever appear in argv or logs.
KEY_LIMITED="dummyKeyLIMITED0000000000000000000000000000"
KEY_GOOD="dummyKeyGOOD1111111111111111111111111111111"
TG_TOKEN="123456789:AAdummyTelegramTokenXYZxyz0123456789"
SLACK_URL="https://hooks.slack.test/services/T000/B000/dummySlackSecretXYZ"
SMTP_PASSWORD="dummySmtpPassw0rd!"

setup_env() {
    rm -rf "$WORK/env"
    mkdir -p "$WORK/env/conf" "$WORK/env/state" "$WORK/env/fix" "$WORK/env/log"
    cat > "$WORK/env/conf/secrets.conf" <<EOF
ABUSEIPDB_API_KEYS="$KEY_LIMITED,$KEY_GOOD"
TELEGRAM_BOT_TOKEN="$TG_TOKEN"
TELEGRAM_CHAT_IDS="111,-100222"
SLACK_WEBHOOK_URLS="$SLACK_URL"
EMAIL_TO="a@example.test,b@example.test"
SMTP_URL="smtps://smtp.example.test:465"
SMTP_USER="mailer@example.test"
SMTP_PASS="$SMTP_PASSWORD"
THRESHOLD=25
HOST_LABEL=testhost
EOF
    cat > "$WORK/env/conf/ips.txt" <<'EOF'
# test pool
192.0.2.1          # clean
192.0.2.2          # newly dirty
192.0.2.3          # will escalate

198.51.100.0/24    # CIDR block
not-an-ip
EOF
    export ABUSE_CHECKER_CONF_DIR="$WORK/env/conf"
    export ABUSE_CHECKER_STATE_DIR="$WORK/env/state"
    export ABUSE_CHECKER_CURL="$HERE/mock_curl.sh"
    export MOCK_FIX="$WORK/env/fix" MOCK_LOG="$WORK/env/log"
    export MOCK_LIMITED_KEYS="$KEY_LIMITED"
    unset MOCK_LEAK USE_CHECK_BLOCK
}

fix_ip() { # ip score total last
    local last="null"; [[ -n "${4:-}" ]] && last="\"$4\""
    printf '{"data":{"ipAddress":"%s","abuseConfidenceScore":%s,"totalReports":%s,"lastReportedAt":%s,"isp":"ISP <%s>","domain":"d.example","countryCode":"US"}}' \
        "$1" "$2" "$3" "$last" "$1" > "$MOCK_FIX/$1.json"
}
fix_block() { # net-with-underscore reports last
    printf '{"data":{"networkAddress":"198.51.100.0","numPossibleHosts":254,"reportedAddress":[{"ipAddress":"198.51.100.9","numReports":%s,"mostRecentReport":"%s","abuseConfidenceScore":60,"countryCode":"NL"}]}}' \
        "$2" "$3" > "$MOCK_FIX/$1.json"
}

run_checker() { # args... ; stores combined output in $OUT, rc in $RC
    OUT="$(bash "$SCRIPT" "$@" 2>&1)"; RC=$?
}
status_of() { grep -P "^\s+[A-Z]+\t\Q$1\E\t" <<< "$OUT" | awk -F'\t' '{gsub(/ /,"",$1); print $1}'; }
state_get() { jq -r --arg ip "$1" ".ips[\$ip].$2" "$ABUSE_CHECKER_STATE_DIR/state.json"; }
report_file() { echo "$ABUSE_CHECKER_STATE_DIR/reports/report_$(date '+%Y-%m-%d').html"; }

# ---------------------------------------------------------------------------
section "Static checks"
for f in abuse-checker.sh install.sh uninstall.sh tests/run_tests.sh tests/mock_curl.sh; do
    if bash -n "$ROOT/$f" 2>/dev/null; then ok "bash -n $f"; else bad "bash -n $f"; fi
    if command -v shellcheck >/dev/null 2>&1; then
        if shellcheck -x "$ROOT/$f" >/dev/null 2>&1; then ok "shellcheck $f"; else bad "shellcheck $f" "$(shellcheck "$ROOT/$f" | head -5)"; fi
    fi
done

# ---------------------------------------------------------------------------
section "Run 1: clean / NEW / CIDR + HTTP 429 key failover"
setup_env
fix_ip 192.0.2.1 0 0
fix_ip 192.0.2.2 55 5 "2026-10-10T10:00:00+00:00"
fix_ip 192.0.2.3 10 3 "2026-10-09T09:00:00+00:00"
fix_block 198.51.100.0_24 4 "2026-10-08T08:00:00+00:00"
run_checker --run
check "run 1 exits 0" test "$RC" -eq 0
check "192.0.2.1 is CLEAN" test "$(status_of 192.0.2.1)" = "CLEAN"
check "192.0.2.2 is NEW" test "$(status_of 192.0.2.2)" = "NEW"
check "192.0.2.3 is NEW (reports>0 below threshold)" test "$(status_of 192.0.2.3)" = "NEW"
check "CIDR 198.51.100.0/24 is NEW" test "$(status_of 198.51.100.0/24)" = "NEW"
check "invalid entry skipped with warning" grep -q "skipping invalid entry: not-an-ip" <<< "$OUT"
check "429 triggered failover warning" grep -q "rate-limited (HTTP 429); failing over" <<< "$OUT"
check "limited key tried exactly once" test "$(wc -l < "$MOCK_LOG/limited.log")" -eq 1
check "all 4 targets served by good key" test "$(grep -c "$KEY_GOOD" "$MOCK_LOG/keys_used.log")" -eq 4
check "check-block endpoint used for CIDR" grep -q 'check-block?network=198.51.100.0%2F24' "$MOCK_LOG/config.log"
check "verbose + maxAgeInDays=30 on /check" grep -q 'check?ipAddress=192.0.2.2&maxAgeInDays=30&verbose' "$MOCK_LOG/config.log"
check "state.json tracks totals" test "$(state_get 192.0.2.3 total)" = "3"
check "state.json marks dirty" test "$(state_get 192.0.2.2 dirty)" = "true"
check "state.json marks clean" test "$(state_get 192.0.2.1 dirty)" = "false"
REPORT="$(report_file)"
check "HTML report generated" test -s "$REPORT"
check "Telegram sendMessage x2 chats" test "$(grep -c '/sendMessage' "$MOCK_LOG/notify.log")" -eq 2
check "Telegram sendDocument x2 chats" test "$(grep -c '/sendDocument' "$MOCK_LOG/notify.log")" -eq 2
check "Slack webhook called" grep -q 'hooks.slack.test' "$MOCK_LOG/notify.log"
check "Slack payload is Block Kit JSON" bash -c 'jq -e ".blocks | length > 3" "$1" >/dev/null' _ "$MOCK_LOG/slack_payload.log"
check "SMTP called with both recipients" grep -q 'mail-rcpt = "b@example.test"' "$MOCK_LOG/config.log"
check "Telegram sendDocument attaches report" grep -q "document=@$REPORT;type=text/html" "$MOCK_LOG/config.log"

section "HTML report validity"
check "starts with doctype" grep -q '^<!DOCTYPE html>' "$REPORT"
check "closes </html>" grep -q '</html>$' "$REPORT"
check "report < 30KB" test "$(wc -c < "$REPORT")" -lt 30720
check "row for 192.0.2.2" grep -q '<td class="m">192.0.2.2</td>' "$REPORT"
check "row for CIDR" grep -q '<td class="m">198.51.100.0/24</td>' "$REPORT"
check "NEW badge present" grep -q 'b-new">NEW' "$REPORT"
check "delta badge +5" grep -q 'class="d">+5<' "$REPORT"
check "ISP is HTML-escaped" grep -q 'ISP &lt;192.0.2.2&gt;' "$REPORT"
check "AbuseIPDB link" grep -q 'https://www.abuseipdb.com/check/192.0.2.2' "$REPORT"
# shellcheck disable=SC2016
check "no external resources" bash -c '! grep -Eq "(src|href)=\"(https?:)?//[^\"]*\.(js|css)" "$1"' _ "$REPORT"
check "summary cards present" grep -q 'Unchanged dirty' "$REPORT"
TAGS_OK=$(awk '{o+=gsub(/<tr/,"");c+=gsub(/<\/tr>/,"")} END{print (o==c)}' "$REPORT")
check "balanced <tr> tags" test "$TAGS_OK" = "1"

# ---------------------------------------------------------------------------
section "Run 2: same data -> UNCHANGED, no alert"
rm -f "$REPORT"; : > "$MOCK_LOG/notify.log"
run_checker --run
check "192.0.2.2 now UNCHANGED" test "$(status_of 192.0.2.2)" = "UNCHANGED"
check "192.0.2.3 now UNCHANGED" test "$(status_of 192.0.2.3)" = "UNCHANGED"
check "CIDR now UNCHANGED" test "$(status_of 198.51.100.0/24)" = "UNCHANGED"
check "no report generated" test ! -e "$REPORT"
check "no notifications sent" test ! -s "$MOCK_LOG/notify.log"
check "log says no alert" grep -q "no NEW or ESCALATED" <<< "$OUT"

# ---------------------------------------------------------------------------
section "Run 3: count increase / newer lastReportedAt -> ESCALATED"
fix_ip 192.0.2.3 30 9 "2026-10-09T09:00:00+00:00"
fix_block 198.51.100.0_24 4 "2026-10-13T08:00:00+00:00"
run_checker --run
check "192.0.2.3 ESCALATED (count 3->9)" test "$(status_of 192.0.2.3)" = "ESCALATED"
check "CIDR ESCALATED (newer lastReportedAt)" test "$(status_of 198.51.100.0/24)" = "ESCALATED"
check "192.0.2.2 still UNCHANGED" test "$(status_of 192.0.2.2)" = "UNCHANGED"
check "state total updated to 9" test "$(state_get 192.0.2.3 total)" = "9"
check "report regenerated" test -s "$REPORT"
check "delta badge +6 in report" grep -q 'class="d">+6<' "$REPORT"
check "ESCALATED badge in report" grep -q 'b-escalated">ESCALATED' "$REPORT"
check "footer mentions unchanged count" grep -q '1 unchanged dirty IP(s)' "$REPORT"
check "notifications sent" test -s "$MOCK_LOG/notify.log"

section "Run 4: dirty -> clean -> dirty again is NEW"
fix_ip 192.0.2.2 0 0
run_checker --run
check "192.0.2.2 CLEAN" test "$(status_of 192.0.2.2)" = "CLEAN"
fix_ip 192.0.2.2 40 1 "2026-10-14T01:00:00+00:00"
run_checker --run
check "192.0.2.2 NEW again" test "$(status_of 192.0.2.2)" = "NEW"

section "--force-full-report"
rm -f "$REPORT"; : > "$MOCK_LOG/notify.log"
run_checker --force-full-report
check "statuses unchanged" test "$(status_of 192.0.2.3)" = "UNCHANGED"
check "report generated anyway" test -s "$REPORT"
check "alert sent anyway" test -s "$MOCK_LOG/notify.log"

# ---------------------------------------------------------------------------
section "All keys rate-limited"
cp "$ABUSE_CHECKER_STATE_DIR/state.json" "$WORK/state.before"
MOCK_LIMITED_KEYS="$KEY_LIMITED,$KEY_GOOD" run_checker --run
check "exits 0 even if API exhausted" test "$RC" -eq 0
check "exhaustion logged" grep -q "all API keys exhausted" <<< "$OUT"
check "previous state preserved" test "$(state_get 192.0.2.3 total)" = "9"

section "USE_CHECK_BLOCK=false expands small CIDR"
setup_env
printf '203.0.113.8/30\n' > "$ABUSE_CHECKER_CONF_DIR/ips.txt"
fix_ip 203.0.113.9 80 2 "2026-10-12T00:00:00+00:00"
USE_CHECK_BLOCK=false run_checker --run
check "2 hosts queried (/30 without net/bcast)" test "$(grep -c "$KEY_GOOD" "$MOCK_LOG/keys_used.log")" -eq 2
check "expanded host NEW" test "$(status_of 203.0.113.9)" = "NEW"
check "other host CLEAN" test "$(status_of 203.0.113.10)" = "CLEAN"

# ---------------------------------------------------------------------------
section "Secret protection"
setup_env
fix_ip 192.0.2.2 55 5 "2026-10-10T10:00:00+00:00"
MOCK_LEAK=1 run_checker --run
ALL_SECRETS=("$KEY_LIMITED" "$KEY_GOOD" "$TG_TOKEN" "$SLACK_URL" "$SMTP_PASSWORD")
leak_argv=0 leak_out=0
for s in "${ALL_SECRETS[@]}"; do
    grep -qF -- "$s" "$MOCK_LOG/argv.log" && leak_argv=1
    grep -qF -- "$s" <<< "$OUT" && leak_out=1
done
check "no secret in curl argv (ps aux safe)" test "$leak_argv" -eq 0
check "secrets delivered via curl --config stdin" grep -qF "Key: $KEY_GOOD" "$MOCK_LOG/config.log"
check "Telegram token only in stdin config" grep -qF "bot$TG_TOKEN/sendMessage" "$MOCK_LOG/config.log"
check "curl always invoked with --config -" bash -c '! grep -v -- "--config -" "$1" | grep -q .' _ "$MOCK_LOG/argv.log"
check "no secret in script stdout/stderr" test "$leak_out" -eq 0
check "leaked URLs were scrubbed to ***REDACTED***" grep -q 'api.telegram.org/bot\*\*\*REDACTED\*\*\*/send' <<< "$OUT"
check "secrets absent from state and report" bash -c '! grep -rqF -e "$1" -e "$2" -e "$3" "$4"' _ "$KEY_GOOD" "$TG_TOKEN" "$SMTP_PASSWORD" "$ABUSE_CHECKER_STATE_DIR"

# Unit test of redact_stream itself (script is sourceable).
REDACTED="$( (
    # shellcheck source=/dev/null
    source "$SCRIPT"
    export ABUSEIPDB_API_KEYS="$KEY_LIMITED,$KEY_GOOD" TELEGRAM_BOT_TOKEN="$TG_TOKEN" SLACK_WEBHOOK_URLS="$SLACK_URL" SMTP_PASS="$SMTP_PASSWORD"
    printf 'k=%s t=%s s=%s p=%s keep=hello\n' "$KEY_GOOD" "$TG_TOKEN" "$SLACK_URL" "$SMTP_PASSWORD" | redact_stream
) )"
check "redact_stream scrubs every secret" test "$REDACTED" = 'k=***REDACTED*** t=***REDACTED*** s=***REDACTED*** p=***REDACTED*** keep=hello'
CFGQ="$( (
    # shellcheck source=/dev/null
    source "$SCRIPT"; cfg_line form-string $'text=a "b" \\c\nline2'
) )"
check "curl config quoting escapes quotes/newlines" test "$CFGQ" = 'form-string = "text=a \"b\" \\c\nline2"'

# ---------------------------------------------------------------------------
section "Management commands"
setup_env
run_checker --dry-run
check "--dry-run exits 0" test "$RC" -eq 0
check "--dry-run did not call curl" test ! -s "$MOCK_LOG/argv.log"
check "--dry-run writes separate state" test -s "$ABUSE_CHECKER_STATE_DIR/state.dryrun.json"
check "--dry-run leaves real state untouched" test ! -e "$ABUSE_CHECKER_STATE_DIR/state.json"
check "--dry-run report written" test -s "$ABUSE_CHECKER_STATE_DIR/reports/report_$(date +%F)_dryrun.html"
run_checker --dry-run
check "second --dry-run: nothing new" grep -q "no NEW or ESCALATED" <<< "$OUT"
run_checker --test-notify
check "--test-notify exits 0" test "$RC" -eq 0
check "--test-notify sent Telegram" grep -q sendDocument "$MOCK_LOG/notify.log"
check "--test-notify report exists" test -s "$ABUSE_CHECKER_STATE_DIR/reports/report_$(date +%F)_test.html"
run_checker --run
run_checker --status
check "--status shows tracked count" grep -q "Tracked     : 4" <<< "$OUT"
check "--status shows last run" grep -q "Last run    : 20" <<< "$OUT"
run_checker --reset-state
check "--reset-state empties state" test "$(jq '.ips | length' "$ABUSE_CHECKER_STATE_DIR/state.json")" = "0"
run_checker --bogus
check "unknown flag exits 2" test "$RC" -eq 2

section "Retention"
old="$ABUSE_CHECKER_STATE_DIR/reports/report_2000-01-01.html"
echo x > "$old"; touch -d '40 days ago' "$old"
fix_ip 192.0.2.2 55 5 "2026-10-10T10:00:00+00:00"
run_checker --run
check "reports older than RETENTION_DAYS deleted" test ! -e "$old"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
(( FAIL == 0 ))
