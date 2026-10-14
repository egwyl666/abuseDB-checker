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
    mkdir -p "$WORK/env/connectors.d" "$WORK/env/shm" "$WORK/env/tmp" "$WORK/env/dropin"
    cp "$ROOT"/connectors/*.sh "$WORK/env/connectors.d/"
    export ABUSE_CHECKER_CONNECTORS_DIR="$WORK/env/connectors.d"
    export ABUSE_CHECKER_RAMDIR="$WORK/env/shm"
    export ABUSE_CHECKER_DROPIN_DIR="$WORK/env/dropin"
    export ABUSE_CHECKER_CRYPTO=openssl
    export TMPDIR="$WORK/env/tmp"
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
for f in abuse-checker.sh install.sh uninstall.sh tests/run_tests.sh tests/mock_curl.sh \
         connectors/10-telegram.sh connectors/20-slack.sh connectors/30-email.sh connectors/99-custom.sh.example; do
    if bash -n "$ROOT/$f" 2>/dev/null; then ok "bash -n $f"; else bad "bash -n $f"; fi
    if command -v shellcheck >/dev/null 2>&1; then
        if shellcheck -s bash -x "$ROOT/$f" >/dev/null 2>&1; then ok "shellcheck $f"; else bad "shellcheck $f" "$(shellcheck -s bash "$ROOT/$f" | head -5)"; fi
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

# ---------------------------------------------------------------------------
section "Connectors: modular loading and broken-file guards"
setup_env
fix_ip 192.0.2.2 55 5 "2026-10-10T10:00:00+00:00"
CD="$ABUSE_CHECKER_CONNECTORS_DIR"
: > "$CD/05-empty.sh"                                          # 0 bytes
printf '   \n\t\n# just a comment\n   # another\n\n' > "$CD/06-blank.sh"
printf 'connector_enabled() { true; }\nconnector_send() { if then; }\n' > "$CD/07-broken.sh"
printf 'SOME_SETTING=1\nhelper() { :; }\n' > "$CD/08-noiface.sh"
printf 'connector_enabled() { true; }\nconnector_send() { echo boom >&2; return 1; }\n' > "$CD/15-failing.sh"
printf 'connector_enabled() { [[ -n "${NOT_CONFIGURED_VAR:-}" ]]; }\nconnector_send() { echo SHOULD-NOT-RUN; }\n' > "$CD/25-disabled.sh"
cp "$ROOT/connectors/99-custom.sh.example" "$CD/40-custom.sh"
cp "$ROOT/connectors/99-custom.sh.example" "$CD/99-custom.sh.example"   # not *.sh: ignored
CUSTOM_URL="https://hooks.slack.test/custom/dummyCustomSecret777"
echo "CUSTOM_WEBHOOK_URL=\"$CUSTOM_URL\"" >> "$ABUSE_CHECKER_CONF_DIR/secrets.conf"
run_checker --run
check "run survives broken connectors (rc 0)" test "$RC" -eq 0
check "warns: empty file" grep -q "05-empty.sh: empty file; skipped" <<< "$OUT"
check "warns: whitespace/comment-only file" grep -q "06-blank.sh: only comments/whitespace; skipped" <<< "$OUT"
check "warns: syntax error file" grep -q "07-broken.sh: syntax error (bash -n failed); skipped" <<< "$OUT"
check "warns: missing interface" grep -q "08-noiface.sh: missing connector_enabled/connector_send; skipped" <<< "$OUT"
check "failing connector logged, others continue" grep -q "connector 15-failing failed" <<< "$OUT"
check "unconfigured connector silently skipped" bash -c '! grep -q SHOULD-NOT-RUN <<< "$1"' _ "$OUT"
check "*.example template not loaded" bash -c '! grep -q "99-custom" <<< "$1"' _ "$OUT"
check "Telegram still delivered" grep -q '/sendDocument' "$MOCK_LOG/notify.log"
check "Slack still delivered" grep -q 'hooks.slack.test/services' "$MOCK_LOG/notify.log"
check "Email still delivered" grep -q '^smtps://' "$MOCK_LOG/notify.log"
check "custom connector (from template) delivered" grep -q 'hooks.slack.test/custom' "$MOCK_LOG/notify.log"
check "custom connector payload valid" bash -c 'grep -q "\"alerts\"" "$1"' _ "$MOCK_LOG/slack_payload.log"
check "custom *WEBHOOK* secret redacted from logs" bash -c '! grep -qF "$1" <<< "$2"' _ "$CUSTOM_URL" "$OUT"
check "custom secret not in curl argv" bash -c '! grep -qF "$1" "$2"' _ "$CUSTOM_URL" "$MOCK_LOG/argv.log"
run_checker --status
check "--status lists valid connectors" grep -q "Connectors  : 10-telegram 15-failing 20-slack 25-disabled 30-email 40-custom" <<< "$OUT"
rm -f "$CD"/*.sh
run_checker --run
check "no connectors at all: still rc 0" test "$RC" -eq 0

section "Empty ips.txt and empty connector variables"
setup_env
printf '# nothing here\n\n   \n# 192.0.2.1\n' > "$ABUSE_CHECKER_CONF_DIR/ips.txt"
run_checker --run
check "comment-only ips.txt: rc 0" test "$RC" -eq 0
check "comment-only ips.txt: warning" grep -q "no valid targets" <<< "$OUT"
setup_env
printf 'ABUSEIPDB_API_KEYS="%s"\nTELEGRAM_BOT_TOKEN=""\nTELEGRAM_CHAT_IDS=""\nSLACK_WEBHOOK_URLS=""\nEMAIL_TO=""\n' "$KEY_GOOD" \
    > "$ABUSE_CHECKER_CONF_DIR/secrets.conf"
fix_ip 192.0.2.2 55 5 "2026-10-10T10:00:00+00:00"
run_checker --run
check "empty connector vars: rc 0" test "$RC" -eq 0
check "empty connector vars: nothing sent" test ! -s "$MOCK_LOG/notify.log"
check "empty connector vars: warning" grep -q "no connector delivered" <<< "$OUT"

# ---------------------------------------------------------------------------
section "Encrypted secrets (OpenSSL tier)"
setup_env
# openssl shim: records argv, then runs the real binary.
mkdir -p "$WORK/bin"
REAL_OPENSSL="$(command -v openssl)"
printf '#!/usr/bin/env bash\nprintf "%%q " "$@" >> "%s"; echo >> "%s"\nexec "%s" "$@"\n' \
    "$WORK/openssl_argv.log" "$WORK/openssl_argv.log" "$REAL_OPENSSL" > "$WORK/bin/openssl"
chmod +x "$WORK/bin/openssl"
: > "$WORK/openssl_argv.log"
OLDPATH="$PATH"; export PATH="$WORK/bin:$PATH"
C="$ABUSE_CHECKER_CONF_DIR"
dec() { "$REAL_OPENSSL" enc -aes-256-cbc -pbkdf2 -iter 100000 -md sha256 -d -pass "file:$C/.master.key" -in "$C/secrets.conf.enc"; }
no_plain_leaks() { # every secret is absent from all files in conf/state/ram/tmp
    local s
    for s in "${ALL_SECRETS[@]}"; do
        grep -rqaF -- "$s" "$C" "$ABUSE_CHECKER_STATE_DIR" "$ABUSE_CHECKER_RAMDIR" "$TMPDIR" 2>/dev/null && return 1
    done
    return 0
}

run_checker --run
check "legacy plain secrets.conf still loads" grep -q "API key #1 rate-limited" <<< "$OUT"
check "legacy plain secrets.conf warns" grep -q "run 'sudo abuse-checker --encrypt-secrets'" <<< "$OUT"
run_checker --encrypt-secrets
check "--encrypt-secrets rc 0" test "$RC" -eq 0
check "plain secrets.conf removed" test ! -e "$C/secrets.conf"
check "secrets.conf.enc created" test -s "$C/secrets.conf.enc"
check "ciphertext has OpenSSL salt header" bash -c 'head -c 8 "$1" | grep -q Salted__' _ "$C/secrets.conf.enc"
check "master key is 256-bit hex" bash -c '[[ "$(tr -d "\n" < "$1")" =~ ^[0-9a-f]{64}$ ]]' _ "$C/.master.key"
check "master key mode 0400" test "$(stat -c %a "$C/.master.key")" = "400"
check "encrypted file mode 0640" test "$(stat -c %a "$C/secrets.conf.enc")" = "640"
check "decrypts back to the original" bash -c 'grep -qF "$1" <<< "$2"' _ "TELEGRAM_BOT_TOKEN=\"$TG_TOKEN\"" "$(dec)"
check "drop-in uses LoadCredential for master key" grep -q "^LoadCredential=master.key:$C/.master.key" "$ABUSE_CHECKER_DROPIN_DIR/10-secrets.conf"
check "no plaintext secret left on disk/RAM/tmp" no_plain_leaks
: > "$MOCK_LOG/notify.log"; : > "$MOCK_LOG/keys_used.log"
fix_ip 192.0.2.2 55 5 "2026-10-10T10:00:00+00:00"
run_checker --reset-state
run_checker --run
check "run with encrypted store: rc 0" test "$RC" -eq 0
check "run with encrypted store: no plain warning" bash -c '! grep -q "plain text" <<< "$1"' _ "$OUT"
check "run with encrypted store: API key used" grep -qF "$KEY_GOOD" "$MOCK_LOG/keys_used.log"
check "run with encrypted store: alerts sent" grep -q sendMessage "$MOCK_LOG/notify.log"
run_checker --status
check "--status reports openssl store" grep -q "Secrets     : openssl store" <<< "$OUT"
check "no plaintext secret left after run" no_plain_leaks

# Service-style load: master key handed over via $CREDENTIALS_DIRECTORY.
mkdir -p "$WORK/creds"; cp "$C/.master.key" "$WORK/creds/master.key"
mv "$C/.master.key" "$WORK/master.bak"
CREDENTIALS_DIRECTORY="$WORK/creds" run_checker --status
check "loads via CREDENTIALS_DIRECTORY/master.key (LoadCredential)" grep -q "API keys    : 2 configured" <<< "$OUT"
run_checker --status
check "missing master key: warns, no crash" grep -q "master key is not readable" <<< "$OUT"
mv "$WORK/master.bak" "$C/.master.key"

# --set-secret: value via stdin, never argv.
NEW_TOKEN="999999999:AAnewDummyTokenViaStdin0000000000"
printf '%s\n' "$NEW_TOKEN" | bash "$SCRIPT" --set-secret TELEGRAM_BOT_TOKEN >/dev/null 2>&1
check "--set-secret updated value" bash -c 'grep -qF "$1" <<< "$2"' _ "TELEGRAM_BOT_TOKEN='$NEW_TOKEN'" "$(dec)"
check "--set-secret kept a single definition" test "$(dec | grep -c '^TELEGRAM_BOT_TOKEN=')" -eq 1
printf 'x\n' | bash "$SCRIPT" --set-secret 'BAD-NAME' >/dev/null 2>&1
check "--set-secret rejects invalid names" test $? -ne 0
ALL_SECRETS+=("$NEW_TOKEN")

# --edit-secrets: plaintext only in a 0600 file inside the RAM dir.
cat > "$WORK/editor.sh" <<EOF
#!/usr/bin/env bash
{ echo "path=\$1"; stat -c 'mode=%a' "\$1"; } > "$WORK/editor.seen"
grep -q 'ABUSEIPDB_API_KEYS' "\$1" && echo seen-plaintext >> "$WORK/editor.seen"
printf "HOST_LABEL='edited-host'\n" >> "\$1"
EOF
chmod +x "$WORK/editor.sh"
EDITOR="$WORK/editor.sh" run_checker --edit-secrets
check "--edit-secrets rc 0" test "$RC" -eq 0
check "editor got a file inside the RAM dir" grep -q "path=$ABUSE_CHECKER_RAMDIR/" "$WORK/editor.seen"
check "RAM file was mode 0600" grep -q "mode=600" "$WORK/editor.seen"
check "editor saw decrypted content" grep -q seen-plaintext "$WORK/editor.seen"
check "RAM file shredded afterwards" test -z "$(ls -A "$ABUSE_CHECKER_RAMDIR")"
check "edit re-encrypted" bash -c 'grep -q "HOST_LABEL=.edited-host." <<< "$1"' _ "$(dec)"
check "still no plaintext file left" no_plain_leaks
cp "$C/secrets.conf.enc" "$WORK/enc.before"
printf '#!/usr/bin/env bash\necho "X=\$(id)" >> "$1"\n' > "$WORK/bad_editor.sh"; chmod +x "$WORK/bad_editor.sh"
EDITOR="$WORK/bad_editor.sh" run_checker --edit-secrets </dev/null
check "invalid edit (command substitution) rejected" test "$RC" -ne 0
check "store unchanged after rejected edit" cmp -s "$C/secrets.conf.enc" "$WORK/enc.before"
check "RAM dir empty after rejected edit" test -z "$(ls -A "$ABUSE_CHECKER_RAMDIR")"
printf '#!/usr/bin/env bash\nexit 0\n' > "$WORK/noop_editor.sh"; chmod +x "$WORK/noop_editor.sh"
EDITOR="$WORK/noop_editor.sh" run_checker --edit-secrets
check "unchanged edit: no re-encryption" grep -q "no changes" <<< "$OUT"

leak=0
for s in "${ALL_SECRETS[@]}"; do grep -qF -- "$s" "$WORK/openssl_argv.log" && leak=1; done
check "openssl never receives secrets in argv" test "$leak" -eq 0
check "openssl key passed as -pass file:" grep -q -- "-pass file:" "$WORK/openssl_argv.log"

# Tampered master key must fail loudly, not run with empty config.
cp "$C/.master.key" "$WORK/master.bak"; chmod 600 "$C/.master.key"
"$REAL_OPENSSL" rand -hex 32 > "$C/.master.key"
run_checker --run
check "wrong master key: aborts with error" bash -c '[[ $1 -ne 0 ]] && grep -q "cannot decrypt" <<< "$2"' _ "$RC" "$OUT"
cp "$WORK/master.bak" "$C/.master.key"
export PATH="$OLDPATH"

if command -v systemd-creds >/dev/null 2>&1 && printf x | systemd-creds encrypt --name=t - - >/dev/null 2>&1; then
    section "Encrypted secrets (systemd-creds tier)"
    setup_env
    ABUSE_CHECKER_CRYPTO=systemd run_checker --encrypt-secrets
    check "systemd tier: secrets.cred created" test -s "$C/secrets.cred"
    check "systemd tier: plain file removed" test ! -e "$C/secrets.conf"
    check "systemd tier: drop-in uses LoadCredentialEncrypted" grep -q "^LoadCredentialEncrypted=secrets:$C/secrets.cred" "$ABUSE_CHECKER_DROPIN_DIR/10-secrets.conf"
    run_checker --status
    check "systemd tier: secrets load" grep -q "API keys    : 2 configured" <<< "$OUT"
    check "systemd tier: no plaintext left" no_plain_leaks
else
    printf '  SKIP systemd-creds tier (systemd-creds unavailable here)\n'
fi

# ---------------------------------------------------------------------------
section "Built-in uninstaller (--uninstall) in a fake root"
mk_root() {
    rm -rf "$WORK/root"; local r="$WORK/root"
    mkdir -p "$r/usr/local/bin" "$r/usr/local/lib/abuse-checker/connectors.d" "$r/etc/abuse-checker" \
             "$r/var/lib/abuse-checker/reports" "$r/etc/systemd/system/abuse-checker.service.d"
    touch "$r/usr/local/bin/abuse-checker" "$r/etc/systemd/system/abuse-checker.service" \
          "$r/etc/systemd/system/abuse-checker.timer" "$r/etc/abuse-checker/secrets.conf.enc" \
          "$r/var/lib/abuse-checker/reports/report_x.html"
}
mk_root
OUT="$(printf '3\n' | AC_ROOT="$WORK/root" ABUSE_CHECKER_ASSUME_TTY=1 bash "$SCRIPT" --uninstall 2>&1)"
check "menu shows option [1]" grep -q "\[1\] Remove application & systemd timer only (KEEP encrypted secrets, ips.txt, and HTML reports)" <<< "$OUT"
check "menu shows option [2]" grep -q "\[2\] Full Purge (Remove everything including" <<< "$OUT"
check "menu shows option [3]" grep -q "\[3\] Cancel" <<< "$OUT"
check "menu lists exact paths" grep -q "$WORK/root/usr/local/bin/abuse-checker" <<< "$OUT"
check "cancel removes nothing" test -e "$WORK/root/usr/local/bin/abuse-checker"
OUT="$(printf '1\n' | AC_ROOT="$WORK/root" ABUSE_CHECKER_ASSUME_TTY=1 bash "$SCRIPT" --uninstall 2>&1)"
check "[1] removes binary" test ! -e "$WORK/root/usr/local/bin/abuse-checker"
check "[1] removes connectors lib" test ! -e "$WORK/root/usr/local/lib/abuse-checker"
check "[1] removes units + drop-ins" test ! -e "$WORK/root/etc/systemd/system/abuse-checker.timer" -a ! -e "$WORK/root/etc/systemd/system/abuse-checker.service.d"
check "[1] keeps encrypted secrets" test -e "$WORK/root/etc/abuse-checker/secrets.conf.enc"
check "[1] keeps reports" test -e "$WORK/root/var/lib/abuse-checker/reports/report_x.html"
mk_root
OUT="$(printf '2\nnope\n' | AC_ROOT="$WORK/root" ABUSE_CHECKER_ASSUME_TTY=1 bash "$SCRIPT" --uninstall 2>&1)"
check "[2] without typed confirmation cancels" test -e "$WORK/root/etc/abuse-checker"
OUT="$(printf '2\npurge\n' | AC_ROOT="$WORK/root" ABUSE_CHECKER_ASSUME_TTY=1 bash "$SCRIPT" --uninstall 2>&1)"
check "[2] purges /etc/abuse-checker" test ! -e "$WORK/root/etc/abuse-checker"
check "[2] purges /var/lib/abuse-checker" test ! -e "$WORK/root/var/lib/abuse-checker"
check "[2] removes binary" test ! -e "$WORK/root/usr/local/bin/abuse-checker"
mk_root
OUT="$(AC_ROOT="$WORK/root" bash "$SCRIPT" --uninstall </dev/null 2>&1)"; RC=$?
check "non-interactive without flag refuses" test "$RC" -ne 0 -a -e "$WORK/root/usr/local/bin/abuse-checker"
OUT="$(AC_ROOT="$WORK/root" bash "$ROOT/uninstall.sh" --keep </dev/null 2>&1)"
check "uninstall.sh --keep wrapper works" test ! -e "$WORK/root/usr/local/bin/abuse-checker" -a -e "$WORK/root/etc/abuse-checker/secrets.conf.enc"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
(( FAIL == 0 ))
