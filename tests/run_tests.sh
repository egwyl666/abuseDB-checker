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
    export ABUSE_CHECKER_GITHUB_RAW="https://raw.githubusercontent.test/owner/repo/main"
    export ABUSE_CHECKER_GITHUB_ARCHIVE="https://github.test/owner/repo/archive/refs/heads/main.tar.gz"
    unset MOCK_REMOTE_SCRIPT MOCK_TARBALL AUTO_UPDATE ABUSE_CHECKER_UPDATE_INSTALLER
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
for f in abuse-checker.sh install.sh uninstall.sh tests/run_tests.sh tests/mock_curl.sh tests/mock_systemctl.sh tests/mock_journalctl.sh tests/mock_pkg.sh tests/mock_wget.sh \
         connectors/10-telegram.sh connectors/20-slack.sh connectors/30-email.sh connectors/40-jira.sh connectors/99-custom.sh.example; do
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
check "--status lists valid connectors" grep -q "Connectors  : 10-telegram 15-failing 20-slack 25-disabled 30-email 40-custom 40-jira" <<< "$OUT"
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

# ---------------------------------------------------------------------------
section "Jira connector"
setup_env
JIRA_TOKEN="dummyJiraApiTokenATATT3xFfGF0abc123"
cat >> "$ABUSE_CHECKER_CONF_DIR/secrets.conf" <<JCONF
JIRA_URL="https://jira.test"
JIRA_EMAIL="secops@example.test"
JIRA_API_TOKEN="$JIRA_TOKEN"
JIRA_PROJECT_KEY="SEC"
JIRA_ISSUE_TYPE="Bug"
JIRA_LABELS="security, vps"
JIRA_PRIORITY="High"
JCONF
JIRA_BASIC="$(printf '%s' "secops@example.test:$JIRA_TOKEN" | base64 -w0)"
fix_ip 192.0.2.2 55 5 "2026-10-10T10:00:00+00:00"
fix_ip 192.0.2.3 10 3 "2026-10-09T09:00:00+00:00"
run_checker --run
JP="$MOCK_LOG/jira_payloads.log"
check "jira: run rc 0" test "$RC" -eq 0
check "jira: searched for an open issue first (v3 search/jql)" grep -q "^GET /rest/api/3/search/jql" "$MOCK_LOG/jira.log"
check "jira: created issue when none open" grep -q "^POST /rest/api/2/issue$" "$MOCK_LOG/jira.log"
check "jira: logged created key" grep -q "Jira: created SEC-42" <<< "$OUT"
check "jira: payload project key" jq -se '.[0].fields.project.key == "SEC"' "$JP"
check "jira: payload issue type" jq -se '.[0].fields.issuetype.name == "Bug"' "$JP"
check "jira: payload priority" jq -se '.[0].fields.priority.name == "High"' "$JP"
check "jira: payload labels incl. host label" jq -se '.[0].fields.labels | index("abuse-checker") and index("abuse-checker-testhost") and index("security") and index("vps")' "$JP"
check "jira: summary is the alert title" jq -se '.[0].fields.summary | test("AbuseIPDB alert for testhost: 2 IP")' "$JP"
check "jira: description has wiki table header" jq -se '.[0].fields.description | contains("||Status||IP / Subnet||Score||")' "$JP"
check "jira: description lists NEW IP with delta" jq -se '.[0].fields.description | contains("|NEW|{{192.0.2.2}}|55%|5 (+5)|")' "$JP"
check "jira: description links AbuseIPDB" jq -se '.[0].fields.description | contains("[check|https://www.abuseipdb.com/check/192.0.2.2]")' "$JP"
check "jira: description escapes ISP markup" jq -se '.[0].fields.description | contains("ISP <192.0.2.2>")' "$JP"
check "jira: HTML report attached" grep -q "^attach /rest/api/2/issue/SEC-42/attachments" "$MOCK_LOG/jira.log"
check "jira: Basic auth sent via stdin config" grep -qxF "Basic $JIRA_BASIC" "$MOCK_LOG/jira_authvalues.log"
check "jira: token not in curl argv" bash -c '! grep -qF -e "$1" -e "$2" "$3"' _ "$JIRA_TOKEN" "$JIRA_BASIC" "$MOCK_LOG/argv.log"
check "jira: token redacted from logs" bash -c '! grep -qF "$1" <<< "$2"' _ "$JIRA_TOKEN" "$OUT"
check "jira: other connectors still delivered" grep -q sendDocument "$MOCK_LOG/notify.log"

# Update mode: an open issue exists -> comment instead of a duplicate issue.
: > "$MOCK_LOG/jira.log"; : > "$JP"
fix_ip 192.0.2.3 30 9 "2026-10-12T09:00:00+00:00"
MOCK_JIRA_EXISTING="SEC-7" run_checker --run
check "jira: comments on existing open issue" grep -q "^POST /rest/api/2/issue/SEC-7/comment" "$MOCK_LOG/jira.log"
check "jira: no duplicate issue created" bash -c '! grep -q "^POST /rest/api/2/issue$" "$1"' _ "$MOCK_LOG/jira.log"
check "jira: comment body shows ESCALATED +6" jq -se '.[0].body | contains("|ESCALATED|{{192.0.2.3}}|30%|9 (+6)|")' "$JP"
check "jira: report attached to existing issue" grep -q "^attach /rest/api/2/issue/SEC-7/attachments" "$MOCK_LOG/jira.log"
check "jira: logged update" grep -q "Jira: updated SEC-7" <<< "$OUT"

# Server/Data Center: v3 search missing -> v2 fallback; no e-mail -> Bearer PAT.
: > "$MOCK_LOG/jira.log"; : > "$MOCK_LOG/jira_authvalues.log"
sed -i '/^JIRA_EMAIL=/d' "$ABUSE_CHECKER_CONF_DIR/secrets.conf"
fix_ip 192.0.2.3 30 12 "2026-10-13T09:00:00+00:00"
MOCK_JIRA_V3_404=1 run_checker --run
check "jira: falls back to /rest/api/2/search" grep -q "^GET /rest/api/2/search" "$MOCK_LOG/jira.log"
check "jira: Bearer PAT when JIRA_EMAIL empty" grep -qxF "Bearer $JIRA_TOKEN" "$MOCK_LOG/jira_authvalues.log"

# JIRA_UPDATE_MODE=create always opens a new issue, without searching.
: > "$MOCK_LOG/jira.log"
echo 'JIRA_UPDATE_MODE="create"' >> "$ABUSE_CHECKER_CONF_DIR/secrets.conf"
fix_ip 192.0.2.3 30 15 "2026-10-14T09:00:00+00:00"
MOCK_JIRA_EXISTING="SEC-7" run_checker --run
check "jira create mode: no search" bash -c '! grep -q search "$1"' _ "$MOCK_LOG/jira.log"
check "jira create mode: new issue" grep -q "^POST /rest/api/2/issue$" "$MOCK_LOG/jira.log"

# API error: logged clearly, run still succeeds, other connectors unaffected.
: > "$MOCK_LOG/notify.log"
fix_ip 192.0.2.3 30 18 "2026-10-14T10:00:00+00:00"
MOCK_JIRA_FAIL=1 run_checker --run
check "jira error: run rc 0" test "$RC" -eq 0
check "jira error: Jira's message surfaced" grep -q "Jira issue creation failed (HTTP 400): issuetype: Specify a valid issue type" <<< "$OUT"
check "jira error: connector marked failed" grep -q "connector 40-jira failed" <<< "$OUT"
check "jira error: Telegram still sent" grep -q sendMessage "$MOCK_LOG/notify.log"

# Not configured -> silently skipped; --test-notify reaches Jira when configured.
setup_env
fix_ip 192.0.2.2 55 5 "2026-10-10T10:00:00+00:00"
run_checker --run
check "jira unconfigured: never called" test ! -s "$MOCK_LOG/jira.log"
printf 'JIRA_URL="https://jira.test"\nJIRA_API_TOKEN="%s"\nJIRA_PROJECT_KEY="SEC"\n' "$JIRA_TOKEN" >> "$ABUSE_CHECKER_CONF_DIR/secrets.conf"
run_checker --test-notify
check "--test-notify creates a Jira issue" grep -q "^POST /rest/api/2/issue$" "$MOCK_LOG/jira.log"
check "--test-notify Jira summary marked TEST" jq -se 'map(select(.fields)) | .[0].fields.summary | startswith("[TEST]")' "$MOCK_LOG/jira_payloads.log"

# ---------------------------------------------------------------------------
section "Jira connector with JIRA_BASE_URL / JIRA_USER_EMAIL"
setup_env
J2_TOKEN="dummyJiraTokenNewNames0987654321zz"
printf 'JIRA_BASE_URL="https://jira.test"\nJIRA_USER_EMAIL="ops@example.test"\nJIRA_API_TOKEN="%s"\nJIRA_PROJECT_KEY="OPS"\nJIRA_ISSUE_TYPE="Incident"\n' "$J2_TOKEN" >> "$ABUSE_CHECKER_CONF_DIR/secrets.conf"
fix_ip 192.0.2.2 55 5 "2026-10-10T10:00:00+00:00"
run_checker --run
check "jira (new names): issue created via POST /rest/api/2/issue" grep -q "^POST /rest/api/2/issue$" "$MOCK_LOG/jira.log"
check "jira (new names): project + issue type" jq -se 'map(select(.fields))[0].fields | .project.key == "OPS" and .issuetype.name == "Incident"' "$MOCK_LOG/jira_payloads.log"
check "jira (new names): summary table in description" jq -se 'map(select(.fields))[0].fields.description | contains("||Status||IP / Subnet||") and contains("{{192.0.2.2}}")' "$MOCK_LOG/jira_payloads.log"
check "jira (new names): report attached (X-Atlassian-Token)" bash -c 'grep -q "^attach /rest/api/2/issue/SEC-42/attachments" "$1" && grep -q "X-Atlassian-Token: no-check" "$2"' _ "$MOCK_LOG/jira.log" "$MOCK_LOG/config.log"
check "jira (new names): attachment is the HTML report" grep -q "form = \"file=@$(report_file);type=text/html\"" "$MOCK_LOG/config.log"
check "jira (new names): Basic auth from JIRA_USER_EMAIL" grep -qxF "Basic $(printf '%s' "ops@example.test:$J2_TOKEN" | base64 -w0)" "$MOCK_LOG/jira_authvalues.log"
check "jira (new names): token never in argv" bash -c '! grep -qF "$1" "$2"' _ "$J2_TOKEN" "$MOCK_LOG/argv.log"
check "jira (new names): token redacted in output" bash -c '! grep -qF "$1" <<< "$2"' _ "$J2_TOKEN" "$OUT"

# ---------------------------------------------------------------------------
section "IP pool management (--add-ip / --del-ip / --list-ips / --edit-ips)"
setup_env
IPF="$ABUSE_CHECKER_CONF_DIR/ips.txt"
fix_ip 192.0.2.2 55 5 "2026-10-10T10:00:00+00:00"
run_checker --run        # gives 192.0.2.2 DIRTY, 192.0.2.1 CLEAN in state.json
cmd() { OUT="$(bash "$SCRIPT" "$@" 2>&1)"; RC=$?; }
chmod 0644 "$IPF"
cmd --add-ip 198.51.100.7 2001:db8::5 203.0.113.0/28 --comment "web tier"
check "--add-ip: rc 0" test "$RC" -eq 0
check "--add-ip: IPv4 added with comment" grep -qE '^198\.51\.100\.7 +# web tier$' "$IPF"
check "--add-ip: IPv6 added" grep -qE '^2001:db8::5 +# web tier$' "$IPF"
check "--add-ip: CIDR added" grep -qE '^203\.0\.113\.0/28 +# web tier$' "$IPF"
check "--add-ip: reports count" grep -q "3 entries added" <<< "$OUT"
check "--add-ip: keeps mode 0644" test "$(stat -c %a "$IPF")" = "644"
cp "$IPF" "$WORK/ips.before"
cmd --add-ip 192.0.2.2 2001:DB8::5
check "--add-ip: duplicate IPv4 skipped" grep -q "skip: 192.0.2.2 is already in" <<< "$OUT"
check "--add-ip: duplicate IPv6 (case-insensitive) skipped" grep -q "skip: 2001:DB8::5 is already in" <<< "$OUT"
check "--add-ip: duplicates leave file unchanged" cmp -s "$IPF" "$WORK/ips.before"
cmd --add-ip 10.0.0.1 999.1.1.1 1.2.3.4/33 2001:db8:::1 hello 2001:db8::/129
check "--add-ip: invalid input -> rc!=0" test "$RC" -ne 0
for bad in 999.1.1.1 1.2.3.4/33 2001:db8:::1 hello 2001:db8::/129; do
    check "--add-ip: rejects $bad" grep -qF "error: invalid IP/CIDR: $bad" <<< "$OUT"
done
check "--add-ip: all-or-nothing (valid 10.0.0.1 not added)" cmp -s "$IPF" "$WORK/ips.before"
cmd --add-ip ::ffff:192.0.2.9 fe80::1 2001:db8:0:0:0:0:0:1
check "--add-ip: accepts compressed/embedded IPv6 forms" bash -c '[[ $1 -eq 0 ]] && grep -q "^::ffff:192.0.2.9" "$2" && grep -q "^fe80::1" "$2"' _ "$RC" "$IPF"

cmd --list-ips
check "--list-ips: header" grep -qE '^# +IP / SUBNET +STATUS +COMMENT' <<< "$OUT"
check "--list-ips: DIRTY with score" grep -qE '^[0-9]+ +192\.0\.2\.2 +DIRTY \(55%\)' <<< "$OUT"
check "--list-ips: CLEAN" grep -qE '^[0-9]+ +192\.0\.2\.1 +CLEAN +clean' <<< "$OUT"
check "--list-ips: UNCHECKED new entry + comment" grep -qE '^[0-9]+ +198\.51\.100\.7 +UNCHECKED +web tier' <<< "$OUT"
check "--list-ips: flags invalid line" grep -qE '^[0-9]+ +not-an-ip +INVALID' <<< "$OUT"
check "--list-ips: numbered from 1" grep -qE '^1 +192\.0\.2\.1 ' <<< "$OUT"
cmd --ips
check "--ips alias works" grep -q "192.0.2.2" <<< "$OUT"

check "state has 192.0.2.2 before delete" jq -e '.ips["192.0.2.2"]' "$ABUSE_CHECKER_STATE_DIR/state.json"
cmd --del-ip 192.0.2.2 198.51.100.0/24 192.0.2.250
check "--del-ip: rc 0 when something removed" test "$RC" -eq 0
check "--del-ip: removed from ips.txt" bash -c '! grep -qE "^192\.0\.2\.2( |$)" "$1" && ! grep -q "^198.51.100.0/24" "$1"' _ "$IPF"
check "--del-ip: other entries kept" grep -q "^192.0.2.1" "$IPF"
check "--del-ip: removed from state.json" jq -e '(.ips | has("192.0.2.2") or has("198.51.100.0/24")) | not' "$ABUSE_CHECKER_STATE_DIR/state.json"
check "--del-ip: other state kept" jq -e '.ips | has("192.0.2.1")' "$ABUSE_CHECKER_STATE_DIR/state.json"
check "--del-ip: reports not found" grep -q "not found: 192.0.2.250" <<< "$OUT"
check "--del-ip: keeps mode 0644" test "$(stat -c %a "$IPF")" = "644"
cmd --rm-ip 2001:DB8::5
check "--rm-ip alias (case-insensitive IPv6)" bash -c '[[ $1 -eq 0 ]] && ! grep -q "^2001:db8::5" "$2"' _ "$RC" "$IPF"
cmd --del-ip 192.0.2.250
check "--del-ip: nothing matched -> rc!=0" test "$RC" -ne 0

printf '#!/usr/bin/env bash\necho "192.0.2.77   # added in editor" >> "$1"\n' > "$WORK/ipedit_ok.sh"; chmod +x "$WORK/ipedit_ok.sh"
EDITOR="$WORK/ipedit_ok.sh" cmd --edit-ips
check "--edit-ips: valid edit saved" bash -c '[[ $1 -eq 0 ]] && grep -q "^192.0.2.77 " "$2"' _ "$RC" "$IPF"
check "--edit-ips: pre-existing invalid line noted, not blocking" grep -q "existing invalid entries.*not-an-ip" <<< "$OUT"
check "--edit-ips: keeps mode 0644" test "$(stat -c %a "$IPF")" = "644"
cp "$IPF" "$WORK/ips.before"
printf '#!/usr/bin/env bash\necho "300.1.1.1" >> "$1"\n' > "$WORK/ipedit_bad.sh"; chmod +x "$WORK/ipedit_bad.sh"
EDITOR="$WORK/ipedit_bad.sh" cmd --edit-ips </dev/null
check "--edit-ips: warns about invalid entry" grep -q "line [0-9]*: 300.1.1.1" <<< "$OUT"
check "--edit-ips: invalid edit not saved without confirmation" bash -c '[[ $1 -ne 0 ]] && cmp -s "$2" "$3"' _ "$RC" "$IPF" "$WORK/ips.before"
check "--edit-ips: temp copy removed" test -z "$(ls -A "$TMPDIR")"

# ---------------------------------------------------------------------------
section "Scheduling (--schedule)"
setup_env
export ABUSE_CHECKER_TIMER_DROPIN_DIR="$WORK/env/timer.d" ABUSE_CHECKER_SYSTEMCTL="$HERE/mock_systemctl.sh"
OVR="$ABUSE_CHECKER_TIMER_DROPIN_DIR/override.conf"
cals() { sed -n 's/^OnCalendar=//p' "$OVR" | paste -sd'|' -; }
cmd --schedule "06:00,18:00"
check "schedule times: rc 0" test "$RC" -eq 0
check "schedule times: clears default OnCalendar first" bash -c 'grep -n "^OnCalendar=" "$1" | head -1 | grep -qx "[0-9]*:OnCalendar="' _ "$OVR"
check "schedule times: two OnCalendar entries" test "$(cals)" = "|*-*-* 06:00:00|*-*-* 18:00:00"
check "schedule: [Timer] section" grep -qx "\[Timer\]" "$OVR"
check "schedule: daemon-reload + restart timer" bash -c 'grep -qx daemon-reload "$1" && grep -qx "restart abuse-checker.timer" "$1"' _ "$MOCK_LOG/systemctl.log"
check "schedule: prints next trigger" grep -q "Timer next trigger:" <<< "$OUT"
cmd --schedule "7:05, 22:30"
check "schedule: pads and trims times" test "$(cals)" = "|*-*-* 07:05:00|*-*-* 22:30:00"
cmd --schedule "every 6h";  check "schedule 'every 6h'" test "$(cals)" = "|*-*-* 00/6:00:00"
cmd --schedule 6h;          check "schedule '6h'" test "$(cals)" = "|*-*-* 00/6:00:00"
cmd --schedule "every 12h"; check "schedule 'every 12h'" test "$(cals)" = "|*-*-* 00/12:00:00"
cmd --schedule hourly;      check "schedule 'hourly'" test "$(cals)" = "|hourly"
cmd --schedule daily;       check "schedule 'daily'" test "$(cals)" = "|*-*-* 06:00:00"
cmd --schedule "2x/day";    check "schedule '2x/day'" test "$(cals)" = "|*-*-* 06:00:00|*-*-* 18:00:00"
cp "$OVR" "$WORK/ovr.before"
cmd --schedule 7h
check "schedule '7h' rejected (must divide 24)" bash -c '[[ $1 -ne 0 ]] && grep -q "must divide 24" <<< "$2" && cmp -s "$3" "$4"' _ "$RC" "$OUT" "$OVR" "$WORK/ovr.before"
cmd --schedule "25:00"
check "schedule '25:00' rejected" bash -c '[[ $1 -ne 0 ]] && cmp -s "$2" "$3"' _ "$RC" "$OVR" "$WORK/ovr.before"
if command -v systemd-analyze >/dev/null 2>&1; then
    cmd --schedule "Mon..Fri *-*-* 09:15:00"
    check "schedule raw OnCalendar accepted" test "$(cals)" = "|Mon..Fri *-*-* 09:15:00"
    check "schedule prints next elapse from systemd-analyze" grep -q "next:" <<< "$OUT"
    cp "$OVR" "$WORK/ovr.before"
    cmd --schedule "every blue moon"
    check "schedule invalid raw rejected by systemd-analyze" bash -c '[[ $1 -ne 0 ]] && grep -q "invalid OnCalendar" <<< "$2" && cmp -s "$3" "$4"' _ "$RC" "$OUT" "$OVR" "$WORK/ovr.before"
else
    printf '  SKIP raw OnCalendar validation (systemd-analyze unavailable)\n'
fi
cmd --schedule show
check "schedule show: custom + current entry" bash -c 'grep -q "custom:" <<< "$1" && grep -q "Mon..Fri\|06:00" <<< "$1"' _ "$OUT"
cmd --schedule reset
check "schedule reset removes override" test ! -e "$OVR"
cmd --schedule show
check "schedule show after reset: default" grep -q "(default)" <<< "$OUT"
check "unit test: schedule_to_calendars" bash -c 'source "$1"; [[ "$(schedule_to_calendars "06:00,14:00,22:00" | paste -sd"|" -)" == "*-*-* 06:00:00|*-*-* 14:00:00|*-*-* 22:00:00" ]]' _ "$SCRIPT"
unset ABUSE_CHECKER_TIMER_DROPIN_DIR

# ---------------------------------------------------------------------------
section "Watchdog (--watchdog-recover) and unit hardening"
setup_env
export ABUSE_CHECKER_SYSTEMCTL="$HERE/mock_systemctl.sh" ABUSE_CHECKER_JOURNALCTL="$HERE/mock_journalctl.sh"
printf 'JIRA_BASE_URL="https://jira.test"\nJIRA_API_TOKEN="dummyJiraWatchdogToken123456"\nJIRA_PROJECT_KEY="SEC"\nJIRA_WATCHDOG_PRIORITY="Highest"\n' >> "$ABUSE_CHECKER_CONF_DIR/secrets.conf"
fix_ip 192.0.2.2 55 5 "2026-10-10T10:00:00+00:00"
run_checker --run
: > "$MOCK_LOG/notify.log"; : > "$MOCK_LOG/systemctl.log"; : > "$MOCK_LOG/jira.log"
run_checker --watchdog-recover
check "watchdog healthy: rc 0" test "$RC" -eq 0
check "watchdog healthy: says healthy" grep -q "watchdog: healthy" <<< "$OUT"
check "watchdog healthy: no alert" test ! -s "$MOCK_LOG/notify.log"

LOCK="$ABUSE_CHECKER_STATE_DIR/.lock"
: > "$LOCK"; touch -d '1 hour ago' "$LOCK"
: > "$MOCK_LOG/config.log"; : > "$MOCK_LOG/slack_payload.log"; : > "$MOCK_LOG/jira_payloads.log"
MOCK_SC_FAILED=1 MOCK_SC_TIMER_INACTIVE=1 MOCK_LEAK_TOKEN="$TG_TOKEN" run_checker --watchdog-recover
check "watchdog: rc 0" test "$RC" -eq 0
check "watchdog: stale lock removed" test ! -e "$LOCK"
check "watchdog: reset-failed on service" grep -qx "reset-failed abuse-checker.service" "$MOCK_LOG/systemctl.log"
check "watchdog: timer restarted" grep -qx "restart abuse-checker.timer" "$MOCK_LOG/systemctl.log"
check "watchdog: read last 15 journal lines" grep -qx -- "-u abuse-checker.service -n 15 --no-pager -o short-iso" "$MOCK_LOG/journalctl.log"
check "watchdog: Telegram [WATCHDOG ALERT]" grep -q 'text=🚨 <b>\[WATCHDOG ALERT\] abuse-checker on testhost crashed and was recovered</b>' "$MOCK_LOG/config.log"
check "watchdog: alert lists problems and actions" bash -c 'grep -q "failed state" "$1" && grep -q "removed stale lock" "$1" && grep -q "restarted abuse-checker.timer" "$1"' _ "$MOCK_LOG/config.log"
check "watchdog: alert includes journal lines" grep -q "line 19" "$MOCK_LOG/config.log"
check "watchdog: journal secret redacted in alert" bash -c 'l="$(grep "failed to connect" "$1")"; [[ -n "$l" ]] && ! grep -qF "$2" <<< "$l" && grep -q "bot\*\*\*REDACTED\*\*\*/sendMessage" <<< "$l"' _ "$MOCK_LOG/config.log" "$TG_TOKEN"
check "watchdog: no report document sent" bash -c '! grep -q sendDocument "$1"' _ "$MOCK_LOG/notify.log"
check "watchdog: Slack alert" grep -q "rotating_light" "$MOCK_LOG/slack_payload.log"
check "watchdog: email high priority + body" bash -c 'grep -q "X-Priority: 1" "$1" && grep -q "Subject: \[WATCHDOG ALERT\]" "$1" && grep -q "Last 15 log lines" "$1"' _ "$MOCK_LOG/mail.log"
check "watchdog: Jira issue with watchdog label + priority" jq -se 'map(select(.fields))[0].fields | (.labels | index("abuse-checker-watchdog")) and .priority.name == "Highest" and (.summary | startswith("[WATCHDOG ALERT]"))' "$MOCK_LOG/jira_payloads.log"
check "watchdog: Jira always creates (no search)" bash -c '! grep -q search "$1"' _ "$MOCK_LOG/jira.log"

: > "$MOCK_LOG/systemctl.log"
MOCK_SC_TIMER_DISABLED=1 run_checker --watchdog-recover
check "watchdog: re-enables disabled timer" grep -qx "enable abuse-checker.timer" "$MOCK_LOG/systemctl.log"

: > "$LOCK"; touch -d '1 hour ago' "$LOCK"
flock "$LOCK" sleep 5 & HOLDER=$!; sleep 0.3
: > "$MOCK_LOG/notify.log"
run_checker --watchdog-recover
check "watchdog: held lock is left alone" bash -c '[[ -e "$1" ]] && grep -q "run is in progress" <<< "$2"' _ "$LOCK" "$OUT"
check "watchdog: held lock alone is not an alert" test ! -s "$MOCK_LOG/notify.log"
kill "$HOLDER" 2>/dev/null; wait "$HOLDER" 2>/dev/null

jq '.lastRun = "2026-01-01T00:00:00Z"' "$ABUSE_CHECKER_STATE_DIR/state.json" > "$WORK/st" && cp "$WORK/st" "$ABUSE_CHECKER_STATE_DIR/state.json"
run_checker --watchdog-recover
check "watchdog: stale lastRun triggers alert" grep -q "no successful run for" <<< "$OUT"
unset ABUSE_CHECKER_SYSTEMCTL ABUSE_CHECKER_JOURNALCTL

U="$ROOT/systemd/abuse-checker.service"
for kv in "Restart=on-failure" "RestartSec=60s" "RuntimeMaxSec=15min" "TimeoutStartSec=15min" \
          "StartLimitIntervalSec=15min" "StartLimitBurst=3" "OnFailure=abuse-checker-watchdog.service"; do
    check "unit: $kv" grep -qx "$kv" "$U"
done
check "unit: StartLimit* in [Unit] section" bash -c 'awk "/^\[Service\]/{exit} /^StartLimitBurst=3/{f=1} END{exit !f}" "$1"' _ "$U"
check "watchdog unit runs --watchdog-recover" grep -qx "ExecStart=/usr/local/bin/abuse-checker --watchdog-recover" "$ROOT/systemd/abuse-checker-watchdog.service"
check "watchdog timer is periodic" grep -q "^OnUnitActiveSec=" "$ROOT/systemd/abuse-checker-watchdog.timer"
if command -v systemd-analyze >/dev/null 2>&1; then
    check "units pass systemd-analyze verify" bash -c 'SYSTEMD_LOG_LEVEL=err systemd-analyze verify --man=no "$@" 2>&1 | grep -v "not executable" | grep -q . && exit 1 || exit 0' _ \
        "$ROOT/systemd/abuse-checker.service" "$ROOT/systemd/abuse-checker.timer" "$ROOT/systemd/abuse-checker-watchdog.service" "$ROOT/systemd/abuse-checker-watchdog.timer"
fi

# ---------------------------------------------------------------------------
section "Verbose abuse details: categories, comments, drill-down"
setup_env
check "category map: 18 -> Brute-Force, 22 -> SSH, 14 -> Port Scan" bash -c 'source "$1"; [[ "$(jq -rn "$JQ_LIB [18,22,14,4,9,23,99] | map(catname) | join(\"|\")")" == "Brute-Force|SSH|Port Scan|DDoS Attack|Open Proxy|IoT Targeted|Category 99" ]]' _ "$SCRIPT"
check "category map covers 1..23" bash -c 'source "$1"; [[ "$(jq -rn "$JQ_LIB [range(1;24)] | map(catname) | map(select(startswith(\"Category \"))) | length")" == 0 ]]' _ "$SCRIPT"
cat > "$MOCK_FIX/192.0.2.2.json" <<'JSON'
{"data":{"ipAddress":"192.0.2.2","abuseConfidenceScore":92,"totalReports":3,"numDistinctUsers":3,
 "lastReportedAt":"2026-10-14T21:17:39+00:00","isp":"Evil Hosting","domain":"evil.example","countryCode":"RU",
 "usageType":"Data Center/Web Hosting/Transit","hostnames":["scan01.evil.example","scan02.evil.example"],
 "reports":[
  {"reportedAt":"2026-10-12T10:00:00+00:00","comment":"Port scan detected on 22,80,443","categories":[14],"reporterId":1,"reporterCountryCode":"US"},
  {"reportedAt":"2026-10-14T21:17:39+00:00","comment":"SSH brute-force login attempt from user root <script>alert(1)</script> & \"quotes\"\nsecond line","categories":[18,22],"reporterId":2,"reporterCountryCode":"DE"},
  {"reportedAt":"2026-10-13T09:00:00+00:00","comment":"Failed password for invalid user admin from 192.0.2.2 port 51234 ssh2","categories":[18,22],"reporterId":3,"reporterCountryCode":"FR"}]}}
JSON
printf '{"data":{"networkAddress":"198.51.100.0","numPossibleHosts":254,"reportedAddress":[
 {"ipAddress":"198.51.100.9","numReports":2,"mostRecentReport":"2026-10-10T08:00:00+00:00","abuseConfidenceScore":20,"countryCode":"NL"},
 {"ipAddress":"198.51.100.77","numReports":30,"mostRecentReport":"2026-10-14T08:00:00+00:00","abuseConfidenceScore":95,"countryCode":"NL"},
 {"ipAddress":"198.51.100.5","numReports":7,"mostRecentReport":"2026-10-12T08:00:00+00:00","abuseConfidenceScore":51,"countryCode":"NL"}]}}' > "$MOCK_FIX/198.51.100.0_24.json"
printf 'JIRA_BASE_URL="https://jira.test"\nJIRA_API_TOKEN="dummyJiraTokenDetails123456"\nJIRA_PROJECT_KEY="SEC"\n' >> "$ABUSE_CHECKER_CONF_DIR/secrets.conf"
run_checker --run
R="$(report_file)"
check "details: run rc 0" test "$RC" -eq 0
check "norm_check: topCategories by frequency, reports newest first, metadata" bash -c 'source "$1"; jq -ce --arg t x "$JQ_LIB $norm_check | .topCategories == [\"Brute-Force\",\"SSH\",\"Port Scan\"] and .reports[0].reportedAt == \"2026-10-14T21:17:39+00:00\" and .reports[0].categories == [\"Brute-Force\",\"SSH\"] and .distinctUsers == 3 and .usage != \"\" and (.hostnames | contains(\"scan02\"))" "$2" >/dev/null' _ "$SCRIPT" "$MOCK_FIX/192.0.2.2.json"
check "norm_block: hosts sorted by score, fields kept" bash -c 'source "$1"; jq -ce --arg t x "$JQ_LIB $norm_block | (.hosts | map(.ipAddress)) == [\"198.51.100.77\",\"198.51.100.5\",\"198.51.100.9\"] and .hosts[0].numReports == 30 and .reportedHosts == 3" "$2" >/dev/null' _ "$SCRIPT" "$MOCK_FIX/198.51.100.0_24.json"
check "report: Top categories + Distinct reporters columns" bash -c 'grep -q "<th>Top categories</th><th>Distinct reporters</th>" "$1"' _ "$R"
check "report: category badges in main row (Brute-Force, SSH, Port Scan)" bash -c 'grep -q "<span class=\"cat\">Brute-Force</span> <span class=\"cat\">SSH</span> <span class=\"cat\">Port Scan</span>" "$1"' _ "$R"
check "report: distinct reporters value" grep -q '<td data-v="3">3</td>' "$R"
check "report: <details> drill-down for IP" grep -q '<details><summary>View 3 report detail(s)</summary>' "$R"
check "report: metadata usage type + hostnames" bash -c 'grep -q "<b>Usage type:</b> Data Center/Web Hosting/Transit" "$1" && grep -q "scan01.evil.example, scan02.evil.example" "$1"' _ "$R"
check "report: sub-table headers" grep -q '<th>Timestamp (UTC)</th><th>Categories</th><th>Reporter</th><th>Comment / log snippet</th>' "$R"
check "report: newest report first" bash -c 'grep "View 3 report detail(s)" "$1" | sed "s/.*View 3 report detail(s)//" | grep -o "<td class=\"m nw\">2026-10-1[234] [0-9:]*</td>" | head -1 | grep -q "2026-10-14 21:17:39"' _ "$R"
check "report: comment shown in <pre>" grep -q '<pre>Failed password for invalid user admin' "$R"
check "report: <script> in comment escaped" grep -qF '&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;quotes&quot;' "$R"
check "report: no raw <script>alert" bash -c '! grep -q "<script>alert" "$1"' _ "$R"
check "report: <details> drill-down for CIDR" grep -q '<details><summary>View 3 reported host(s)</summary>' "$R"
check "report: CIDR sub-hosts sorted by score desc" bash -c 'grep -o "<td class=\"m\">198\.51\.100\.[0-9]*</td>" "$1" | sed "s/<[^>]*>//g" | paste -sd, - | grep -qx "198.51.100.77,198.51.100.5,198.51.100.9"' _ "$R"
check "report: CIDR sub-host link" grep -q 'href="https://www.abuseipdb.com/check/198.51.100.77"' "$R"
check "report: CIDR reported-host count column" grep -q '3 <small>hosts</small>' "$R"
check "report: Expand all button" grep -q '<button id="xa" type="button">Expand all</button>' "$R"
check "report: clean IP has no drill-down" bash -c '! grep -A1 "192.0.2.1</td>" "$1" | grep -q "<details>"' _ "$R"
check "report: still < 30KB" test "$(wc -c < "$R")" -lt 30720
check "report: balanced <details>" bash -c '[[ $(grep -o "<details>" "$1" | wc -l) == $(grep -o "</details>" "$1" | wc -l) ]]' _ "$R"
check "telegram: categories line" grep -q '🏷 \[Brute-Force, SSH, Port Scan\]' "$MOCK_LOG/config.log"
check "telegram: escaped latest comment (newline collapsed)" grep -qF '💬 <code>SSH brute-force login attempt from user root &lt;script&gt;alert(1)&lt;/script&gt; &amp; \"quotes\" second line</code>' "$MOCK_LOG/config.log"
check "telegram: CIDR worst hosts" grep -qF '💬 <code>worst hosts: 198.51.100.77 (95%), 198.51.100.5 (51%), 198.51.100.9 (20%)</code>' "$MOCK_LOG/config.log"
check "slack: categories + escaped quote" bash -c 'jq -e "[.blocks[].text.text? // empty] | map(select(contains(\":label: [Brute-Force, SSH, Port Scan]\") and contains(\"> SSH brute-force login attempt from user root &lt;script&gt;\"))) | length == 1" "$1"' _ "$MOCK_LOG/slack_payload.log"
check "email: Categories + Why lines" bash -c 'grep -q "Categories: \[Brute-Force, SSH, Port Scan\]" "$1" && grep -q "Why: SSH brute-force login attempt from user root" "$1"' _ "$MOCK_LOG/mail.log"
check "jira: Categories + Why columns" jq -se 'map(select(.fields))[0].fields.description | contains("||Categories||Why (latest report)||") and contains("Brute-Force, SSH, Port Scan |SSH brute-force login attempt from user root")' "$MOCK_LOG/jira_payloads.log"
LONG="$(jq -r 'map(select(.fields))[0].fields.description' "$MOCK_LOG/jira_payloads.log" | grep -o 'SSH brute-force login attempt[^|]*' | head -1)"
check "snippet truncated to 120 chars + ellipsis" bash -c '[[ ${#1} -le 122 ]]' _ "$LONG"
run_checker --dry-run
check "dry-run mock carries verbose reports" bash -c 'grep -qE "SSH brute-force login attempt|Port scan: 1,024|Spam relay" "$1"' _ "$ABUSE_CHECKER_STATE_DIR/reports/report_$(date +%F)_dryrun.html"
check "dry-run mock CIDR breakdown" grep -q 'View 3 reported host(s)' "$ABUSE_CHECKER_STATE_DIR/reports/report_$(date +%F)_dryrun.html"

# ---------------------------------------------------------------------------
section "System doctor (--doctor / --check-system) and dependency auto-install"
setup_env
export ABUSE_CHECKER_PKG_MGR=apt-get ABUSE_CHECKER_PKG_CMD="$HERE/mock_pkg.sh"
export ABUSE_CHECKER_FAKE_MISSING_FILE="$WORK/fake_missing" ABUSE_CHECKER_SYSTEMCTL="$HERE/mock_systemctl.sh"
export ABUSE_CHECKER_DOCTOR_URL="https://api.abuseipdb.com/api/v2/check"
printf 'PRETTY_NAME="Testix 1.0"\nID=testix\n' > "$WORK/os-release"; export ABUSE_CHECKER_OS_RELEASE="$WORK/os-release"
: > "$ABUSE_CHECKER_FAKE_MISSING_FILE"
echo '{"version":1,"ips":{}}' > "$ABUSE_CHECKER_STATE_DIR/state.json"
mkdir -p "$ABUSE_CHECKER_STATE_DIR/reports"; chmod 750 "$ABUSE_CHECKER_STATE_DIR" "$ABUSE_CHECKER_STATE_DIR/reports"; chmod 640 "$ABUSE_CHECKER_STATE_DIR/state.json"
chmod 755 "$ABUSE_CHECKER_CONF_DIR"; chmod 600 "$ABUSE_CHECKER_CONF_DIR/secrets.conf"; chmod 777 "$ABUSE_CHECKER_CONF_DIR/ips.txt"
printf 'jq\nflock\nca-certificates\n' > "$ABUSE_CHECKER_FAKE_MISSING_FILE"
: > "$MOCK_LOG/pkg.log"
cmd --doctor
check "doctor: OS line" grep -qF "[OK]    OS: Testix 1.0" <<< "$OUT"
check "doctor: package manager" grep -qF "[OK]    package manager: apt-get" <<< "$OUT"
check "doctor: refreshed metadata" grep -qx "update -qq" "$MOCK_LOG/pkg.log"
check "doctor: installed mapped packages non-interactively" grep -qx "install -y -qq --no-install-recommends jq util-linux ca-certificates" "$MOCK_LOG/pkg.log"
check "doctor: [FIXED] per installed dependency" bash -c 'grep -qF "[FIXED] installed missing dependency: jq" <<< "$1" && grep -qF "[FIXED] installed missing dependency: flock" <<< "$1"' _ "$OUT"
check "doctor: bash version check" grep -qE '^\[OK\] +bash [0-9.]+.* \(>= 4\.4\)' <<< "$OUT"
check "doctor: tool versions" bash -c 'grep -q "^\[OK\]    curl " <<< "$1" && grep -q "^\[OK\]    jq " <<< "$1" && grep -q "^\[OK\]    openssl " <<< "$1"' _ "$OUT"
check "doctor: fixed ips.txt mode 777 -> 644" bash -c 'grep -q "^\[FIXED\] .*ips.txt: 777" <<< "$1" && [[ $(stat -c %a "$2") == 644 ]]' _ "$OUT" "$ABUSE_CHECKER_CONF_DIR/ips.txt"
check "doctor: warns about plain-text secrets" grep -qF "secrets stored in plain text" <<< "$OUT"
check "doctor: systemd timers checked" grep -qF "[OK]    abuse-checker.timer enabled and active" <<< "$OUT"
check "doctor: failed service reset" bash -c '! grep -q "abuse-checker.service is in the failed" <<< "$1"' _ "$OUT"
check "doctor: disk space" grep -qE '^\[OK\] +free disk space' <<< "$OUT"
check "doctor: HTTPS connectivity" grep -qF "HTTPS to api.abuseipdb.com reachable (HTTP 200)" <<< "$OUT"
check "doctor: summary line" grep -qE '^Summary: [0-9]+ OK, [0-9]+ fixed, [0-9]+ warning\(s\)$' <<< "$OUT"
check "doctor: rc!=0 while warnings remain" test "$RC" -ne 0
cmd --check-system --upgrade-os
check "--check-system --upgrade-os runs non-interactive upgrade" grep -qx -- "-y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade" "$MOCK_LOG/pkg.log"
check "--check-system: upgrade reported" grep -qF "[FIXED] system packages upgraded" <<< "$OUT"
printf 'jq\n' > "$ABUSE_CHECKER_FAKE_MISSING_FILE"
MOCK_PKG_FAIL=1 cmd --doctor
check "doctor: failed install -> [WARN] missing" grep -qF "[WARN]  missing dependency: jq" <<< "$OUT"
for pm in dnf yum apk pacman zypper; do
    : > "$MOCK_LOG/pkg.log"; printf 'flock\nawk\n' > "$ABUSE_CHECKER_FAKE_MISSING_FILE"
    ABUSE_CHECKER_PKG_MGR=$pm cmd --install-deps
    case $pm in
        dnf|yum) want="-q -y install gawk util-linux" ;;
        apk) want="-q add --no-cache gawk flock" ;;
        pacman) want="-S --needed --noconfirm gawk util-linux" ;;
        zypper) want="--non-interactive --quiet install --no-recommends gawk util-linux" ;;
    esac
    check "--install-deps with $pm: $want" bash -c '[[ $1 -eq 0 ]] && grep -qxF -- "$2" "$3"' _ "$RC" "$want" "$MOCK_LOG/pkg.log"
done
: > "$ABUSE_CHECKER_FAKE_MISSING_FILE"; : > "$MOCK_LOG/pkg.log"
cmd --install-deps
check "--install-deps: nothing missing -> no package calls" bash -c '[[ $1 -eq 0 ]] && [[ ! -s "$2" ]] && grep -q "all dependencies present" <<< "$3"' _ "$RC" "$MOCK_LOG/pkg.log" "$OUT"
printf 'jq\n' > "$ABUSE_CHECKER_FAKE_MISSING_FILE"
fix_ip 192.0.2.2 55 5 "2026-10-10T10:00:00+00:00"
run_checker --run
check "runtime root fallback installs missing jq and runs" bash -c '[[ $1 -eq 0 ]] && grep -q "installed missing dependencies: jq" <<< "$2"' _ "$RC" "$OUT"
printf 'jq\n' > "$ABUSE_CHECKER_FAKE_MISSING_FILE"
AUTO_INSTALL_DEPS=false run_checker --run
check "AUTO_INSTALL_DEPS=false: clear error instead" bash -c '[[ $1 -ne 0 ]] && grep -q "missing dependencies: jq (run: sudo abuse-checker --doctor)" <<< "$2"' _ "$RC" "$OUT"
unset ABUSE_CHECKER_PKG_MGR ABUSE_CHECKER_PKG_CMD ABUSE_CHECKER_FAKE_MISSING_FILE ABUSE_CHECKER_SYSTEMCTL ABUSE_CHECKER_DOCTOR_URL ABUSE_CHECKER_OS_RELEASE
check "install.sh: --upgrade-os flag + exact prompt" bash -c 'grep -q -- "--upgrade-os) UPGRADE_OS=true" "$1" && grep -qF "Would you like to update system packages (OS upgrade) before installing? [y/N]" "$1"' _ "$ROOT/install.sh"
check "install.sh: uses --install-deps before installing" grep -q 'deps_args=(--install-deps)' "$ROOT/install.sh"
check "install.sh: /dev/tty only used in the terminal foreground" grep -q 'elif tty_in_foreground && { exec 3</dev/tty; }' "$ROOT/install.sh"
check "install.sh: every prompt read has a timeout in pipe mode" bash -c '[[ $(grep -c "read -r[^|]*-u \"\$TTY_FD\"" "$1") -gt 0 && $(grep "read -r[^|]*-u \"\$TTY_FD\"" "$1" | grep -vc "READ_T\[@\]") -eq 0 ]]' _ "$ROOT/install.sh"
check "install.sh: piped, no foreground tty -> defaults, no hang" bash -c 'out="$(cd "$1" && timeout 30 bash -c "ABUSE_CHECKER_TTY_FOREGROUND=0 ABUSE_CHECKER_BOOTSTRAP_DRYRUN=1 bash -n install.sh && echo ok")"; [[ "$out" == ok ]]' _ "$ROOT"
check "README recommends sudo bash -c \"\$(curl ...)\"" grep -q '^sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/egwyl666/abuseDB-checker/main/install.sh)"$' "$ROOT/README.md"

# ---------------------------------------------------------------------------
section "Self-update: --check-update / --update / AUTO_UPDATE"
setup_env
CUR_VER="$(sed -n 's/^readonly AC_VERSION="\(.*\)"$/\1/p' "$SCRIPT")"
mk_release() { # dir-name version [corrupt-target]
    local d="$WORK/rel/$1/abuseDB-checker-main"
    rm -rf "$WORK/rel/$1"; mkdir -p "$d"
    cp -r "$ROOT/abuse-checker.sh" "$ROOT/install.sh" "$ROOT/uninstall.sh" "$ROOT/connectors" \
          "$ROOT/systemd" "$ROOT/config" "$d/"
    sed -i "s/^readonly AC_VERSION=\".*\"$/readonly AC_VERSION=\"$2\"/" "$d/abuse-checker.sh"
    [[ -n "${3:-}" ]] && printf '\nif then fi\n' >> "$d/$3"
    tar -czf "$WORK/rel/$1.tar.gz" -C "$WORK/rel/$1" abuseDB-checker-main
    cp "$d/abuse-checker.sh" "$WORK/rel/$1.remote.sh"
}
mk_release good 9.9.9
mk_release same "$CUR_VER"
mk_release badscript 9.9.9 abuse-checker.sh
mk_release badconn 9.9.9 connectors/20-slack.sh
printf 'this is not a tarball' > "$WORK/rel/garbage.tar.gz"

# A fake "installed" binary plus an installer stub standing in for install.sh.
INSTALLED="$WORK/installed/abuse-checker"
mkdir -p "$WORK/installed"; cp "$SCRIPT" "$INSTALLED"; cp "$INSTALLED" "$WORK/installed.orig"
cat > "$WORK/installer_stub.sh" <<STUB
#!/usr/bin/env bash
echo "\$1" >> "$WORK/installer.log"
cp "\$1/abuse-checker.sh" "$INSTALLED"
STUB
chmod +x "$WORK/installer_stub.sh"
export ABUSE_CHECKER_UPDATE_INSTALLER="$WORK/installer_stub.sh"
upd() { OUT="$(bash "$INSTALLED" "$@" 2>&1)"; RC=$?; }
reset_installed() { cp "$WORK/installed.orig" "$INSTALLED"; rm -f "$WORK/installer.log"; }

MOCK_REMOTE_SCRIPT="$WORK/rel/good.remote.sh" upd --check-update
check "--check-update shows installed version" grep -q "Installed : v$CUR_VER" <<< "$OUT"
check "--check-update finds newer v9.9.9" grep -q "Update available -> run: sudo abuse-checker --update" <<< "$OUT"
check "--check-update queried raw abuse-checker.sh" grep -q "raw.githubusercontent.test/owner/repo/main/abuse-checker.sh" "$MOCK_LOG/update.log"
MOCK_REMOTE_SCRIPT="$WORK/rel/same.remote.sh" upd --check-update
check "--check-update: same version is up to date" grep -q "Up to date." <<< "$OUT"
upd --check-update
check "--check-update: GitHub unreachable -> error, rc!=0" bash -c '[[ $1 -ne 0 ]] && grep -q "could not determine" <<< "$2"' _ "$RC" "$OUT"

reset_installed
MOCK_TARBALL="$WORK/rel/good.tar.gz" upd --update
check "--update good release: rc 0" test "$RC" -eq 0
check "--update ran installer on verified tree" grep -q "abuseDB-checker-main" "$WORK/installer.log"
check "--update installed v9.9.9" grep -q 'AC_VERSION="9.9.9"' "$INSTALLED"
check "--update logged version change" grep -q "updated v$CUR_VER -> v9.9.9" <<< "$OUT"
check "--update temp dir cleaned up" test -z "$(ls -A "$TMPDIR")"
reset_installed
MOCK_TARBALL="$WORK/rel/good.tar.gz" upd --self-update
check "--self-update alias works" grep -q 'AC_VERSION="9.9.9"' "$INSTALLED"

reset_installed
MOCK_TARBALL="$WORK/rel/badscript.tar.gz" upd --update
check "corrupted remote script: rejected (rc!=0)" test "$RC" -ne 0
check "corrupted remote script: clear message" grep -q "abuse-checker.sh fails 'bash -n'; update rejected" <<< "$OUT"
check "corrupted remote script: installer NOT run" test ! -e "$WORK/installer.log"
check "corrupted remote script: installed binary untouched" cmp -s "$INSTALLED" "$WORK/installed.orig"
check "installed binary still works afterwards" bash "$INSTALLED" --version
MOCK_TARBALL="$WORK/rel/badconn.tar.gz" upd --update
check "corrupted remote connector: rejected" bash -c '[[ $1 -ne 0 ]] && grep -q "20-slack.sh fails" <<< "$2"' _ "$RC" "$OUT"
check "corrupted remote connector: binary untouched" cmp -s "$INSTALLED" "$WORK/installed.orig"
MOCK_TARBALL="$WORK/rel/garbage.tar.gz" upd --update
check "garbage archive: rejected, untouched" bash -c '[[ $1 -ne 0 ]] && cmp -s "$2" "$3"' _ "$RC" "$INSTALLED" "$WORK/installed.orig"
upd --update
check "download failure: rejected, untouched" bash -c '[[ $1 -ne 0 ]] && cmp -s "$2" "$3"' _ "$RC" "$INSTALLED" "$WORK/installed.orig"
MOCK_TARBALL="$WORK/rel/same.tar.gz" upd --update
check "same version: already up to date, no install" bash -c 'grep -q "already up to date" <<< "$1" && [[ ! -e "$2" ]]' _ "$OUT" "$WORK/installer.log"
MOCK_TARBALL="$WORK/rel/same.tar.gz" upd --update --force
check "--update --force reinstalls same version" test -e "$WORK/installer.log"

# AUTO_UPDATE=notify (default): banner in report, Telegram, Slack, email.
reset_installed
fix_ip 192.0.2.2 55 5 "2026-10-10T10:00:00+00:00"
: > "$MOCK_LOG/update.log"
MOCK_REMOTE_SCRIPT="$WORK/rel/good.remote.sh" run_checker --run
NOTICE="Update available: v9.9.9 -> Run 'sudo abuse-checker --update'"
check "notify: logged" grep -qF "$NOTICE" <<< "$OUT"
check "notify: banner in HTML report" grep -qF "Update available: v9.9.9 -&gt; Run 'sudo abuse-checker --update'" "$(report_file)"
check "notify: in Telegram message" grep -qF "Update available: v9.9.9 -&gt; Run" "$MOCK_LOG/config.log"
check "notify: in Slack footer" grep -qF "$NOTICE" "$MOCK_LOG/slack_payload.log"
check "notify: nothing installed" test ! -e "$WORK/installer.log"
check "notify: check cached in state dir" jq -e '.latest == "9.9.9"' "$ABUSE_CHECKER_STATE_DIR/update-check.json"
MOCK_REMOTE_SCRIPT="$WORK/rel/good.remote.sh" run_checker --run
check "notify: only one GitHub check per day" test "$(grep -c 'abuse-checker.sh$' "$MOCK_LOG/update.log")" -eq 1
MOCK_REMOTE_SCRIPT="$WORK/rel/same.remote.sh" run_checker --run
check "notify: cached result still shown same day" grep -qF "$NOTICE" <<< "$OUT"
rm -f "$ABUSE_CHECKER_STATE_DIR/update-check.json"
MOCK_REMOTE_SCRIPT="$WORK/rel/same.remote.sh" run_checker --run
check "notify: no banner when up to date" bash -c '! grep -q "Update available" <<< "$1"' _ "$OUT"
run_checker --run
check "notify: GitHub unreachable does not break the run" test "$RC" -eq 0

# AUTO_UPDATE=false: never contacts GitHub.
rm -f "$ABUSE_CHECKER_STATE_DIR/update-check.json"; : > "$MOCK_LOG/update.log"
AUTO_UPDATE=false MOCK_REMOTE_SCRIPT="$WORK/rel/good.remote.sh" run_checker --run
check "false: no GitHub request" test ! -s "$MOCK_LOG/update.log"
check "false: no banner" bash -c '! grep -q "Update available" <<< "$1"' _ "$OUT"
AUTO_UPDATE=false MOCK_TARBALL="$WORK/rel/good.tar.gz" MOCK_REMOTE_SCRIPT="$WORK/rel/good.remote.sh" upd --auto-update
check "false: --auto-update does nothing" test ! -e "$WORK/installer.log"
AUTO_UPDATE=notify MOCK_TARBALL="$WORK/rel/good.tar.gz" MOCK_REMOTE_SCRIPT="$WORK/rel/good.remote.sh" upd --auto-update
check "notify: --auto-update does not install" test ! -e "$WORK/installer.log"

# AUTO_UPDATE=true: --auto-update (ExecStartPre=+) installs verified updates.
rm -f "$ABUSE_CHECKER_STATE_DIR/update-check.json"
AUTO_UPDATE=true MOCK_TARBALL="$WORK/rel/good.tar.gz" MOCK_REMOTE_SCRIPT="$WORK/rel/good.remote.sh" upd --auto-update
check "true: --auto-update installs v9.9.9" bash -c '[[ $1 -eq 0 ]] && grep -q "AC_VERSION=\"9.9.9\"" "$2"' _ "$RC" "$INSTALLED"
reset_installed; rm -f "$ABUSE_CHECKER_STATE_DIR/update-check.json"
AUTO_UPDATE=true MOCK_TARBALL="$WORK/rel/badscript.tar.gz" MOCK_REMOTE_SCRIPT="$WORK/rel/good.remote.sh" upd --auto-update
check "true: corrupted update never fails the service (rc 0)" test "$RC" -eq 0
check "true: corrupted update keeps old binary" cmp -s "$INSTALLED" "$WORK/installed.orig"
check "true: failure is logged" grep -q "automatic update failed" <<< "$OUT"
unset ABUSE_CHECKER_UPDATE_INSTALLER

section "One-line installer bootstrap (curl | bash)"
mkdir -p "$WORK/elsewhere"
BOOT_OUT="$(cd "$WORK/elsewhere" && MOCK_TARBALL="$WORK/rel/good.tar.gz" ABUSE_CHECKER_BOOTSTRAP_DRYRUN=1 bash < "$ROOT/install.sh" 2>&1)"; RC=$?
check "piped install.sh downloads + verifies tarball" bash -c '[[ $1 -eq 0 ]] && grep -q "bootstrap verified" <<< "$2"' _ "$RC" "$BOOT_OUT"
check "bootstrap used the archive URL" grep -q "github.test/owner/repo/archive/refs/heads/main.tar.gz" "$MOCK_LOG/update.log"
BOOT_OUT="$(cd "$WORK/elsewhere" && MOCK_TARBALL="$WORK/rel/badscript.tar.gz" ABUSE_CHECKER_BOOTSTRAP_DRYRUN=1 bash < "$ROOT/install.sh" 2>&1)"; RC=$?
check "bootstrap rejects corrupted archive" bash -c '[[ $1 -ne 0 ]] && grep -q "syntax check failed" <<< "$2"' _ "$RC" "$BOOT_OUT"
BOOT_OUT="$(cd "$WORK/elsewhere" && ABUSE_CHECKER_BOOTSTRAP_DRYRUN=1 bash < "$ROOT/install.sh" 2>&1)"; RC=$?
check "bootstrap reports download failure" bash -c '[[ $1 -ne 0 ]] && grep -q "download failed" <<< "$2"' _ "$RC" "$BOOT_OUT"
check "bootstrap leaves no temp dirs" test -z "$(ls -A "$TMPDIR")"

section "Bootstrap on a bare system without curl"
boot() { (cd "$WORK/elsewhere" && ABUSE_CHECKER_BOOTSTRAP_DRYRUN=1 ABUSE_CHECKER_PKG_CMD="$HERE/mock_pkg.sh" \
          ABUSE_CHECKER_FAKE_MISSING_FILE="$WORK/fake_missing" "$@" bash < "$ROOT/install.sh" 2>&1); }
printf 'curl\nca-certificates\n' > "$WORK/fake_missing"; : > "$MOCK_LOG/pkg.log"; : > "$MOCK_LOG/update.log"
BOOT_OUT="$(boot env ABUSE_CHECKER_PKG_MGR=apt-get MOCK_TARBALL="$WORK/rel/good.tar.gz")"; RC=$?
check "no curl: installs curl + ca-certificates first (apt-get)" grep -qx "install -y -qq --no-install-recommends curl ca-certificates" "$MOCK_LOG/pkg.log"
check "no curl: refreshes package metadata" grep -qx "update -qq" "$MOCK_LOG/pkg.log"
check "no curl: then downloads with curl and verifies" bash -c '[[ $1 -eq 0 ]] && grep -q "bootstrap verified" <<< "$2" && grep -q "archive/refs/heads/main.tar.gz" "$3"' _ "$RC" "$BOOT_OUT" "$MOCK_LOG/update.log"
for pm in dnf yum apk pacman zypper; do
    printf 'curl\ntar\ngzip\n' > "$WORK/fake_missing"; : > "$MOCK_LOG/pkg.log"
    BOOT_OUT="$(boot env ABUSE_CHECKER_PKG_MGR=$pm MOCK_TARBALL="$WORK/rel/good.tar.gz")"; RC=$?
    case $pm in
        dnf|yum) want="-q -y install curl tar gzip" ;;
        apk) want="-q add --no-cache curl tar gzip" ;;
        pacman) want="-Sy --needed --noconfirm curl tar gzip" ;;
        zypper) want="--non-interactive --quiet install --no-recommends curl tar gzip" ;;
    esac
    check "no curl/tar/gzip with $pm: '$want'" bash -c '[[ $1 -eq 0 ]] && grep -qxF -- "$2" "$3"' _ "$RC" "$want" "$MOCK_LOG/pkg.log"
done
printf 'curl\n' > "$WORK/fake_missing"; : > "$MOCK_LOG/update.log"
BOOT_OUT="$(boot env ABUSE_CHECKER_PKG_MGR=apt-get MOCK_PKG_FAIL=1 ABUSE_CHECKER_WGET="$HERE/mock_wget.sh" MOCK_TARBALL="$WORK/rel/good.tar.gz")"; RC=$?
check "curl install fails -> falls back to wget" bash -c '[[ $1 -eq 0 ]] && grep -q "downloading with wget" <<< "$2" && grep -q "^wget https://github.test/owner/repo/archive/refs/heads/main.tar.gz" "$3"' _ "$RC" "$BOOT_OUT" "$MOCK_LOG/update.log"
check "wget path still verifies the archive" grep -q "bootstrap verified" <<< "$BOOT_OUT"
BOOT_OUT="$(boot env ABUSE_CHECKER_PKG_MGR=apt-get MOCK_PKG_FAIL=1 ABUSE_CHECKER_WGET="$HERE/mock_wget.sh" MOCK_TARBALL="$WORK/rel/badscript.tar.gz")"; RC=$?
check "wget path rejects a corrupted archive" bash -c '[[ $1 -ne 0 ]] && grep -q "syntax check failed" <<< "$2"' _ "$RC" "$BOOT_OUT"
BOOT_OUT="$(boot env ABUSE_CHECKER_PKG_MGR=apt-get MOCK_PKG_FAIL=1 ABUSE_CHECKER_WGET=/nonexistent/wget)"; RC=$?
check "no curl, no wget, install fails -> clear error" bash -c '[[ $1 -ne 0 ]] && grep -q "neither curl nor wget is available" <<< "$2"' _ "$RC" "$BOOT_OUT"
: > "$WORK/fake_missing"; : > "$MOCK_LOG/pkg.log"
BOOT_OUT="$(boot env ABUSE_CHECKER_PKG_MGR=apt-get MOCK_TARBALL="$WORK/rel/good.tar.gz")"
check "everything present -> no package manager calls" test ! -s "$MOCK_LOG/pkg.log"
check "bootstrap tests leave no temp dirs" test -z "$(ls -A "$TMPDIR")"
check "wizard reads answers from /dev/tty" grep -q 'exec 3</dev/tty' "$ROOT/install.sh"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
(( FAIL == 0 ))
