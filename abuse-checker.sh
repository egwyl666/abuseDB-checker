#!/usr/bin/env bash
# abuse-checker - daily AbuseIPDB monitoring for a pool of IPs/CIDRs.
# Pure Bash + curl + jq + coreutils. See README.md.
set -euo pipefail
umask 027

readonly AC_VERSION="1.1.0"

# ---------------------------------------------------------------------------
# Paths (overridable through the environment, mainly for tests)
# ---------------------------------------------------------------------------
CONF_DIR="${ABUSE_CHECKER_CONF_DIR:-/etc/abuse-checker}"
SECRETS_FILE="${ABUSE_CHECKER_SECRETS:-$CONF_DIR/secrets.conf}"
STATE_DIR="${ABUSE_CHECKER_STATE_DIR:-/var/lib/abuse-checker}"
CURL_BIN="${ABUSE_CHECKER_CURL:-curl}"
SERVICE_USER="abusechecker"

TMPD=""
RAM_FILES=()
RAM_COPY=""
MODE="run"
DRY_RUN=false
FORCE_FULL=false
KEY_IDX=0
API_KEYS=()

# ---------------------------------------------------------------------------
# Logging and secret redaction
# ---------------------------------------------------------------------------
log()  { printf '%s [%s] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$1" "$2" >&2; }
info() { log INFO "$*"; }
warn() { log WARN "$*"; }
die()  { log ERROR "$*"; exit 1; }

# Newline-separated list of every configured secret (keys, tokens, webhooks).
secret_list() {
    local v item
    local -a vals=("${ABUSEIPDB_API_KEYS:-}" "${TELEGRAM_BOT_TOKEN:-}" "${SLACK_WEBHOOK_URLS:-}" "${SMTP_PASS:-}")
    # Custom connectors: any variable whose name looks secret is scrubbed too.
    for v in $(compgen -v | grep -E '(TOKEN|_KEY|_KEYS|PASS|PASSWORD|SECRET|WEBHOOK)' || true); do
        [[ "$v" == "MASTER_KEY" ]] && continue
        vals+=("${!v:-}")
    done
    for v in "${vals[@]}"; do
        IFS=',' read -r -a _parts <<< "$v"
        for item in "${_parts[@]}"; do
            item="$(trim "$item")"
            # Ignore trivially short values so we never scrub ordinary words.
            [[ ${#item} -ge 6 ]] && printf '%s\n' "$item"
        done
    done
    return 0
}

# Filter stdin -> stdout, replacing every secret with ***REDACTED***.
# Secrets reach awk via its own environment (not argv), so they never show
# up in `ps aux`; awk index() does literal (non-regex) matching.
redact_stream() {
    AC_REDACT_LIST="$(secret_list)" awk '
        BEGIN { n = split(ENVIRON["AC_REDACT_LIST"], s, "\n") }
        {
            line = $0
            for (i = 1; i <= n; i++) {
                if (s[i] == "") continue
                out = ""
                while ((p = index(line, s[i])) > 0) {
                    out = out substr(line, 1, p - 1) "***REDACTED***"
                    line = substr(line, p + length(s[i]))
                }
                line = out line
            }
            print line
            fflush()
        }'
}

install_redaction() {
    [[ "${AC_NO_REDACT:-}" == "1" ]] && return 0
    exec > >(redact_stream) 2> >(redact_stream >&2)
}

trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }

# Split a comma-separated list into lines, trimmed, empties dropped.
split_csv() {
    local item
    IFS=',' read -r -a _items <<< "${1:-}"
    for item in "${_items[@]}"; do
        item="$(trim "$item")"
        [[ -n "$item" ]] && printf '%s\n' "$item"
    done
    return 0
}

# ---------------------------------------------------------------------------
# Secure curl: URL and headers travel through `--config -` (stdin), never argv
# ---------------------------------------------------------------------------
cfg_quote() {
    local v="${1//\\/\\\\}"
    v="${v//\"/\\\"}"; v="${v//$'\n'/\\n}"; v="${v//$'\r'/\\r}"; v="${v//$'\t'/\\t}"
    printf '"%s"' "$v"
}
cfg_line()  { printf '%s = %s\n' "$1" "$(cfg_quote "$2")"; }

# secure_curl <config-text> [extra non-secret curl args...]
secure_curl() {
    local cfg="$1"; shift
    printf '%s\n' "$cfg" | "$CURL_BIN" --silent --show-error --config - "$@"
}

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
load_config() {
    load_secrets
    IPS_FILE="${IPS_FILE:-$CONF_DIR/ips.txt}"
    STATE_FILE="${STATE_FILE:-$STATE_DIR/state.json}"
    REPORT_DIR="${REPORT_DIR:-$STATE_DIR/reports}"
    API_BASE="${ABUSEIPDB_API_BASE:-https://api.abuseipdb.com/api/v2}"
    THRESHOLD="${THRESHOLD:-25}"
    MAX_AGE_DAYS="${MAX_AGE_DAYS:-30}"
    USE_CHECK_BLOCK="${USE_CHECK_BLOCK:-true}"
    EXPAND_MAX_HOSTS="${EXPAND_MAX_HOSTS:-256}"
    RETENTION_DAYS="${RETENTION_DAYS:-30}"
    REQUEST_DELAY="${REQUEST_DELAY:-0}"
    EMAIL_FROM="${EMAIL_FROM:-abuse-checker@$(hostname 2>/dev/null || echo localhost)}"
    HOST_LABEL="${HOST_LABEL:-$(hostname 2>/dev/null || echo vps)}"
    mapfile -t API_KEYS < <(split_csv "${ABUSEIPDB_API_KEYS:-}")
    [[ "$THRESHOLD" =~ ^[0-9]+$ ]] || die "THRESHOLD must be an integer"
    [[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || die "RETENTION_DAYS must be an integer"
}

require_tools() {
    local t
    for t in jq awk sed date mktemp; do
        command -v "$t" >/dev/null 2>&1 || die "missing dependency: $t"
    done
    command -v "$CURL_BIN" >/dev/null 2>&1 || die "missing dependency: curl"
}

# ---------------------------------------------------------------------------
# Target parsing and CIDR handling
# ---------------------------------------------------------------------------
is_ipv4() {
    local ip="$1" o
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
}
is_ipv6() { [[ "$1" =~ ^[0-9a-fA-F:]+$ && "$1" == *:* ]]; }

# Print one valid target per line (comments and blanks ignored).
read_targets() {
    local file="$1" line addr prefix
    [[ -r "$file" ]] || die "IP list not readable: $file"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="$(trim "$line")"
        [[ -z "$line" ]] && continue
        addr="${line%%/*}"
        prefix=""
        [[ "$line" == */* ]] && prefix="${line#*/}"
        if is_ipv4 "$addr"; then
            if [[ -n "$prefix" ]] && ! { [[ "$prefix" =~ ^[0-9]+$ ]] && (( prefix <= 32 )); }; then
                warn "skipping invalid CIDR: $line"; continue
            fi
        elif is_ipv6 "$addr"; then
            if [[ -n "$prefix" ]] && ! { [[ "$prefix" =~ ^[0-9]+$ ]] && (( prefix <= 128 )); }; then
                warn "skipping invalid CIDR: $line"; continue
            fi
        else
            warn "skipping invalid entry: $line"; continue
        fi
        printf '%s\n' "$line"
    done < "$file" | awk '!seen[$0]++'
}

ip2int() { local IFS=.; read -r a b c d <<< "$1"; echo $(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d )); }
int2ip() { local n=$1; echo "$(( (n >> 24) & 255 )).$(( (n >> 16) & 255 )).$(( (n >> 8) & 255 )).$(( n & 255 ))"; }

# Expand an IPv4 CIDR into its host addresses (network/broadcast skipped for <= /30).
expand_cidr() {
    local cidr="$1" addr="${1%/*}" prefix="${1#*/}" base size i start end
    size=$(( 1 << (32 - prefix) ))
    base=$(( $(ip2int "$addr") & ~(size - 1) & 0xFFFFFFFF ))
    start=$base; end=$(( base + size - 1 ))
    if (( prefix <= 30 )); then start=$(( base + 1 )); end=$(( base + size - 2 )); fi
    for (( i = start; i <= end; i++ )); do int2ip "$i"; done
    : "$cidr"
}

urlencode() {
    local s="$1" out="" c i
    for (( i = 0; i < ${#s}; i++ )); do
        c="${s:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) out+="$c" ;;
            *) out+="$(printf '%%%02X' "'$c")" ;;
        esac
    done
    printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# AbuseIPDB API with multi-key failover
# ---------------------------------------------------------------------------
# api_get <endpoint> <query-string> <out-body-file>
# returns 0 ok, 1 request error, 2 all keys exhausted
api_get() {
    local endpoint="$1" query="$2" out="$3" hdr code remaining cfg
    hdr="$TMPD/headers"
    while (( KEY_IDX < ${#API_KEYS[@]} )); do
        cfg="$(cfg_line url "$API_BASE/$endpoint?$query")
$(cfg_line header "Key: ${API_KEYS[$KEY_IDX]}")
$(cfg_line header "Accept: application/json")"
        : > "$hdr"
        code="$(secure_curl "$cfg" --max-time 30 --retry 2 --retry-delay 2 \
                -o "$out" -D "$hdr" -w '%{http_code}')" || code="000"
        remaining="$(awk -F': *' 'tolower($1)=="x-ratelimit-remaining" {gsub(/\r/,"",$2); print $2}' "$hdr" | tail -n1)"
        case "$code" in
            200)
                if [[ "$remaining" == "0" ]]; then
                    warn "API key #$(( KEY_IDX + 1 )) reached its daily quota; switching to next key"
                    KEY_IDX=$(( KEY_IDX + 1 ))
                fi
                return 0 ;;
            429)
                warn "API key #$(( KEY_IDX + 1 )) rate-limited (HTTP 429); failing over"
                KEY_IDX=$(( KEY_IDX + 1 )) ;;
            401|403)
                warn "API key #$(( KEY_IDX + 1 )) rejected (HTTP $code); failing over"
                KEY_IDX=$(( KEY_IDX + 1 )) ;;
            *)
                warn "AbuseIPDB request for '$endpoint' failed (HTTP $code)"
                return 1 ;;
        esac
    done
    return 2
}

# Normalize an API response into one result object (jq programs, not shell).
# shellcheck disable=SC2016
norm_check='.data | {target:$t, kind:"ip", score:(.abuseConfidenceScore // 0),
    total:(.totalReports // 0), last:(.lastReportedAt // null), isp:(.isp // ""),
    domain:(.domain // ""), country:(.countryCode // "")}'
# shellcheck disable=SC2016
norm_block='.data as $d | ($d.reportedAddress // []) as $r | {target:$t, kind:"cidr",
    score:([$r[].abuseConfidenceScore] | max // 0),
    total:([$r[].numReports] | add // 0),
    last:([$r[].mostRecentReport | select(. != null)] | max),
    isp:("Subnet: \($r | length) of \($d.numPossibleHosts // "?") hosts reported"),
    domain:"", country:([$r[].countryCode | select(. != null)] | unique | join(","))}'

# Deterministic mock response used by --dry-run / --test-notify.
mock_response() {
    local endpoint="$1" target="$2" h ts
    h=$(printf '%s' "$target" | cksum | awk '{print $1 % 4}')
    ts="2026-01-15T08:30:00+00:00"  # fixed so repeated dry-runs are stable
    if [[ "$endpoint" == "check" ]]; then
        case "$h" in
            0) jq -n --arg ip "$target" '{data:{ipAddress:$ip,abuseConfidenceScore:0,totalReports:0,lastReportedAt:null,isp:"Example Clean ISP",domain:"clean.example",countryCode:"DE"}}' ;;
            1) jq -n --arg ip "$target" --arg ts "$ts" '{data:{ipAddress:$ip,abuseConfidenceScore:12,totalReports:2,lastReportedAt:$ts,isp:"Mock Hosting LLC",domain:"mock.example",countryCode:"NL"}}' ;;
            2) jq -n --arg ip "$target" --arg ts "$ts" '{data:{ipAddress:$ip,abuseConfidenceScore:87,totalReports:41,lastReportedAt:$ts,isp:"Bad Actor Networks",domain:"bad.example",countryCode:"US"}}' ;;
            *) jq -n --arg ip "$target" --arg ts "$ts" '{data:{ipAddress:$ip,abuseConfidenceScore:45,totalReports:7,lastReportedAt:$ts,isp:"Shared VPS Ltd",domain:"vps.example",countryCode:"FR"}}' ;;
        esac
    else
        jq -n --arg n "$target" --arg ts "$ts" '{data:{networkAddress:($n|split("/")[0]),numPossibleHosts:256,
            reportedAddress:[{ipAddress:"198.51.100.7",numReports:3,mostRecentReport:$ts,abuseConfidenceScore:33,countryCode:"GB"}]}}'
    fi
}

# Query one target; append a normalized JSON line to $results.
check_target() {
    local target="$1" results="$2" endpoint query filter body rc=0
    body="$TMPD/body.json"
    if [[ "$target" == */* ]]; then
        endpoint="check-block"; filter="$norm_block"
        query="network=$(urlencode "$target")&maxAgeInDays=$MAX_AGE_DAYS"
    else
        endpoint="check"; filter="$norm_check"
        query="ipAddress=$(urlencode "$target")&maxAgeInDays=$MAX_AGE_DAYS&verbose"
    fi
    if $DRY_RUN; then
        mock_response "$endpoint" "$target" > "$body"
    else
        api_get "$endpoint" "$query" "$body" || rc=$?
    fi
    if (( rc == 0 )) && jq -e '.data' "$body" >/dev/null 2>&1; then
        jq -c --arg t "$target" "$filter" "$body" >> "$results"
    else
        local msg="request failed"
        (( rc == 2 )) && msg="all API keys exhausted"
        (( rc == 0 )) && msg="$(jq -r '.errors[0].detail // "invalid response"' "$body" 2>/dev/null || echo 'invalid response')"
        jq -cn --arg t "$target" --arg e "$msg" '{target:$t, error:$e}' >> "$results"
        return "$rc"
    fi
}

collect_results() {
    local results="$1" target ip rc
    local -a targets
    : > "$results"
    mapfile -t targets < <(read_targets "$IPS_FILE")
    if (( ${#targets[@]} == 0 )); then
        warn "no valid targets in $IPS_FILE (only comments/blank lines?); nothing to check"
        return 0
    fi
    if ! $DRY_RUN && (( ${#API_KEYS[@]} == 0 )); then
        die "ABUSEIPDB_API_KEYS is not configured"
    fi
    : > "$results"
    for target in "${targets[@]}"; do
        if [[ "$target" == */* && "$USE_CHECK_BLOCK" != "true" ]] && is_ipv4 "${target%/*}" \
           && (( (1 << (32 - ${target#*/})) <= EXPAND_MAX_HOSTS )); then
            while IFS= read -r ip; do
                rc=0; check_target "$ip" "$results" || rc=$?
                (( rc == 2 )) && break 2
            done < <(expand_cidr "$target")
            continue
        fi
        rc=0; check_target "$target" "$results" || rc=$?
        if (( rc == 2 )); then
            warn "all API keys exhausted; remaining targets will be checked next run"
            break
        fi
        [[ "$REQUEST_DELAY" != "0" ]] && sleep "$REQUEST_DELAY"
    done
    info "checked $(wc -l < "$results" | tr -d ' ') target(s)"
}

# ---------------------------------------------------------------------------
# Stateful diff engine
# ---------------------------------------------------------------------------
# classify <state.json> <results.jsonl> -> JSON array with status + delta
classify() {
    jq -s --slurpfile st "$1" --argjson th "$THRESHOLD" '
        def ts: if . == null then "" else sub("\\+00:00$"; "Z") end;
        ($st[0].ips // {}) as $prev
        | map(. as $r | $prev[$r.target] as $p
            | if $r.error then . + {status:"ERROR", delta:0, score:0, total:0}
              else
                (($r.score > $th) or ($r.total > 0)) as $dirty
                | . + {dirty:$dirty, delta:($r.total - ($p.total // 0)),
                       status:(if ($dirty | not) then "CLEAN"
                               elif ($p == null) or ($p.dirty != true) then "NEW"
                               elif ($r.total > ($p.total // 0)) or (($r.last | ts) > ($p.last | ts)) then "ESCALATED"
                               else "UNCHANGED" end)}
              end)' "$2"
}

# new_state <state.json> <classified.json> <targets.json> -> new state on stdout
# Entries for targets still configured but not checked this run (e.g. API
# quota exhausted) are kept; targets removed from ips.txt are dropped.
new_state() {
    jq --slurpfile c "$2" --slurpfile tg "$3" --arg now "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" '
        (.ips // {}) as $old
        | ($old | with_entries(select(.key as $k | $tg[0] | index($k)))) as $kept
        | {version:1, lastRun:$now,
           ips: (reduce $c[0][] as $r ($kept;
                 if $r.status == "ERROR" then
                     (if $old[$r.target] then .[$r.target] = $old[$r.target] else . end)
                 else .[$r.target] = {score:$r.score, total:$r.total, last:$r.last,
                         dirty:$r.dirty, lastChecked:$now,
                         firstFlagged:(if $r.dirty then ($old[$r.target].firstFlagged // $now) else null end)}
                 end))}' "$1"
}

ensure_state() {
    local f="$1"
    if [[ ! -s "$f" ]] || ! jq -e 'type == "object"' "$f" >/dev/null 2>&1; then
        [[ -s "$f" ]] && warn "state file $f is corrupt; starting fresh"
        echo '{"version":1,"lastRun":null,"ips":{}}' > "$f"
    fi
}

write_atomic() {
    local dest="$1" src="$2" tmp
    tmp="$(mktemp "$(dirname "$dest")/.tmp.XXXXXX")"
    cat "$src" > "$tmp"
    chmod 0640 "$tmp"
    mv -f "$tmp" "$dest"
}

# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------
# render_report <classified.json> <out.html> <title-suffix>
render_report() {
    local data="$1" out="$2" suffix="${3:-}" stats rows now
    now="$(date '+%Y-%m-%d %H:%M %Z')"
    stats="$(jq -r '[length, (map(select(.status=="CLEAN"))|length),
        (map(select(.status=="NEW"))|length), (map(select(.status=="ESCALATED"))|length),
        (map(select(.status=="UNCHANGED"))|length), (map(select(.status=="ERROR"))|length)] | @tsv' "$data")"
    local total clean new esc unch err
    IFS=$'\t' read -r total clean new esc unch err <<< "$stats"
    rows="$(jq -r '
        def order: {"NEW":0,"ESCALATED":1,"UNCHANGED":2,"ERROR":3,"CLEAN":4}[.status];
        def sc: if .score >= 75 then "s-hi" elif .score >= 25 then "s-md" elif .score > 0 then "s-lo" else "s-0" end;
        sort_by(order, -.score)[] |
        "<tr data-s=\"\(order)\"><td><span class=\"b b-\(.status|ascii_downcase)\">\(.status)</span></td>"
        + "<td class=\"m\">\(.target|@html)</td>"
        + "<td data-v=\"\(.score)\"><span class=\"sc \(sc)\">\(.score)%</span></td>"
        + "<td data-v=\"\(.total)\">\(.total)"
        + (if .delta > 0 then " <span class=\"d\">+\(.delta)</span>" elif .delta < 0 then " <span class=\"dn\">\(.delta)</span>" else "" end) + "</td>"
        + "<td>\((.isp // "") | @html)" + (if (.domain // "") != "" then "<br><small>\(.domain|@html)</small>" else "" end)
        + (if .error then "<br><small class=\"err\">\(.error|@html)</small>" else "" end) + "</td>"
        + "<td>\((.country // "") | @html)</td>"
        + "<td data-v=\"\(.last // "")\">\((.last // "-") | sub("T"; " ") | sub("\\+00:00$"; " UTC") | @html)</td>"
        + "<td><a class=\"btn\" target=\"_blank\" rel=\"noopener\" href=\"https://www.abuseipdb.com/check/\(.target|@uri)\">AbuseIPDB</a></td></tr>"
    ' "$data")"
    cat > "$out" <<HTML
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Abuse report ${HOST_LABEL} ${suffix}</title>
<style>
:root{--bg:#f5f6f8;--fg:#1d2330;--card:#fff;--mut:#6b7280;--line:#e5e7eb}
@media (prefers-color-scheme:dark){:root{--bg:#11151c;--fg:#e5e7eb;--card:#1a202b;--mut:#9ca3af;--line:#2a3140}}
*{box-sizing:border-box}body{margin:0;padding:16px;font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mut);margin-bottom:16px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:16px}
.c{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}.c b{display:block;font-size:24px}.c span{color:var(--mut);font-size:12px}
.c.new b{color:#dc2626}.c.esc b{color:#ea580c}.c.unch b{color:#ca8a04}.c.clean b{color:#16a34a}
input{width:100%;max-width:360px;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);margin-bottom:10px}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;min-width:760px}th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{cursor:pointer;user-select:none;font-size:12px;text-transform:uppercase;color:var(--mut)}th:after{content:" \2195";opacity:.4}
.m{font-family:ui-monospace,Menlo,Consolas,monospace}small{color:var(--mut)}.err{color:#dc2626}
.b,.sc,.d,.dn{display:inline-block;padding:2px 7px;border-radius:999px;font-size:11px;font-weight:600;color:#fff}
.b-new{background:#dc2626}.b-escalated{background:#ea580c}.b-unchanged{background:#ca8a04}.b-clean{background:#16a34a}.b-error{background:#6b7280}
.s-hi{background:#b91c1c}.s-md{background:#ea580c}.s-lo{background:#ca8a04}.s-0{background:#16a34a}.d{background:#dc2626}.dn{background:#6b7280}
.btn{display:inline-block;padding:4px 10px;border-radius:6px;background:#2563eb;color:#fff;text-decoration:none;font-size:12px}
footer{color:var(--mut);margin-top:12px;font-size:12px}
</style></head><body>
<h1>AbuseIPDB report &mdash; ${HOST_LABEL} ${suffix}</h1>
<div class="sub">Generated ${now} &middot; threshold ${THRESHOLD}% &middot; window ${MAX_AGE_DAYS} days</div>
<div class="cards">
<div class="c"><b>${total}</b><span>Total checked</span></div>
<div class="c clean"><b>${clean}</b><span>Clean</span></div>
<div class="c new"><b>${new}</b><span>Newly flagged (NEW)</span></div>
<div class="c esc"><b>${esc}</b><span>Escalated</span></div>
<div class="c unch"><b>${unch}</b><span>Unchanged dirty</span></div>
<div class="c"><b>${err}</b><span>Errors</span></div>
</div>
<input id="q" type="search" placeholder="Filter by IP, ISP, country, status...">
<div class="wrap"><table id="t"><thead><tr>
<th>Status</th><th>IP / Subnet</th><th>Abuse score</th><th>Reports (+delta)</th><th>ISP / Domain</th><th>Country</th><th>Last reported</th><th>Link</th>
</tr></thead><tbody>
${rows}
</tbody></table></div>
<footer>${unch} unchanged dirty IP(s) were already known and not re-alerted. abuse-checker v${AC_VERSION}</footer>
<script>
(function(){var t=document.getElementById('t'),b=t.tBodies[0],q=document.getElementById('q');
q.oninput=function(){var v=q.value.toLowerCase();[].forEach.call(b.rows,function(r){r.style.display=r.textContent.toLowerCase().indexOf(v)>-1?'':'none'})};
[].forEach.call(t.tHead.rows[0].cells,function(h,i){var asc=true;h.onclick=function(){var rs=[].slice.call(b.rows);
function k(r){var c=r.cells[i];if(i===0)return +r.getAttribute('data-s');var v=c.getAttribute('data-v');if(v!==null){return isNaN(v)||v===''?v:+v}return c.textContent.toLowerCase()}
rs.sort(function(x,y){var a=k(x),c=k(y);return (a>c?1:a<c?-1:0)*(asc?1:-1)});asc=!asc;rs.forEach(function(r){b.appendChild(r)})}})})();
</script></body></html>
HTML
    chmod 0640 "$out"
}

prune_reports() {
    [[ -d "$REPORT_DIR" ]] || return 0
    find "$REPORT_DIR" -maxdepth 1 -type f -name 'report_*.html' -mtime +"$RETENTION_DAYS" -print -delete 2>/dev/null \
        | while IFS= read -r f; do info "pruned old report $(basename "$f")"; done
    return 0
}

# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------
# Alertable entries: NEW/ESCALATED, or every dirty one when forced.
alert_items() {
    if $FORCE_FULL; then
        jq -c '[.[] | select(.status=="NEW" or .status=="ESCALATED" or .status=="UNCHANGED")]' "$1"
    else
        jq -c '[.[] | select(.status=="NEW" or .status=="ESCALATED")]' "$1"
    fi
}

summary_counts() {
    jq -r '"total=\(length) clean=\(map(select(.status=="CLEAN"))|length) new=\(map(select(.status=="NEW"))|length) escalated=\(map(select(.status=="ESCALATED"))|length) unchanged=\(map(select(.status=="UNCHANGED"))|length) errors=\(map(select(.status=="ERROR"))|length)"' "$1"
}

plain_summary() {
    local data="$1" title="$2"
    jq -r --arg title "$title" --argjson force "$FORCE_FULL" '
        def item: "  [\(.status)] \(.target)  score \(.score)%  reports \(.total)" + (if .delta > 0 then " (+\(.delta))" else "" end) + (if (.isp//"") != "" then "  \(.isp)" else "" end);
        "\($title)",
        "Checked: \(length) | Clean: \(map(select(.status=="CLEAN"))|length) | New: \(map(select(.status=="NEW"))|length) | Escalated: \(map(select(.status=="ESCALATED"))|length) | Errors: \(map(select(.status=="ERROR"))|length)",
        "",
        (.[] | select(.status=="NEW" or .status=="ESCALATED" or ($force and .status=="UNCHANGED")) | item),
        "",
        "\(map(select(.status=="UNCHANGED"))|length) unchanged dirty IP(s) not re-alerted."' "$data"
}

# ---------------------------------------------------------------------------
# Connectors (connectors.d/*.sh)
# ---------------------------------------------------------------------------
connectors_dir() {
    if [[ -n "${ABUSE_CHECKER_CONNECTORS_DIR:-}" ]]; then
        printf '%s' "$ABUSE_CHECKER_CONNECTORS_DIR"
    elif [[ -d "$LIB_DIR/connectors.d" ]]; then
        printf '%s' "$LIB_DIR/connectors.d"
    else
        # Running from a source checkout.
        printf '%s' "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/connectors"
    fi
}

# Print the connector files that pass every guard; warn about the rest.
valid_connectors() {
    local dir f
    dir="$(connectors_dir)"
    [[ -d "$dir" ]] || { warn "connector directory $dir not found; no notifications"; return 0; }
    for f in "$dir"/*.sh; do
        [[ -e "$f" ]] || continue
        if [[ ! -f "$f" || ! -r "$f" ]]; then
            warn "connector $(basename "$f"): not a readable file; skipped"
        elif [[ ! -s "$f" ]]; then
            warn "connector $(basename "$f"): empty file; skipped"
        elif ! grep -vqE '^[[:space:]]*(#|$)' "$f"; then
            warn "connector $(basename "$f"): only comments/whitespace; skipped"
        elif ! bash -n "$f" 2>/dev/null; then
            warn "connector $(basename "$f"): syntax error (bash -n failed); skipped"
        elif ! ( # shellcheck source=/dev/null
                 . "$f" >/dev/null 2>&1 && declare -F connector_enabled >/dev/null \
                 && declare -F connector_send >/dev/null ); then
            warn "connector $(basename "$f"): missing connector_enabled/connector_send; skipped"
        else
            printf '%s\n' "$f"
        fi
    done
    return 0
}

# notify_all <classified.json> <report.html> <title>
notify_all() {
    local f name rc sent=0
    while IFS= read -r f; do
        name="$(basename "$f" .sh)"
        rc=0
        (
            unset -f connector_enabled connector_send
            CONNECTOR_NAME=""
            # shellcheck source=/dev/null
            . "$f"
            connector_enabled || exit 3
            info "connector ${CONNECTOR_NAME:-$name}: delivering"
            connector_send "$@"
        ) || rc=$?
        case "$rc" in
            0) sent=$((sent + 1)) ;;
            3) ;;  # not configured
            *) warn "connector $name failed (exit $rc)" ;;
        esac
    done < <(valid_connectors)
    (( sent > 0 )) || warn "no connector delivered the alert (none configured?)"
    return 0
}

# ---------------------------------------------------------------------------
# Encrypted secrets store
#   Tier 1: systemd-creds   -> secrets.cred  (LoadCredentialEncrypted=)
#   Tier 2: OpenSSL AES-256 -> secrets.conf.enc + .master.key (LoadCredential=)
#   Legacy: plain secrets.conf (still loaded, with a warning)
# Plaintext only ever exists in pipes or in a 0600 file on RAM (/dev/shm).
# Keys are passed to openssl as `-pass file:` so nothing secret is in argv.
# ---------------------------------------------------------------------------
ENC_FILE="$CONF_DIR/secrets.conf.enc"
CRED_FILE="$CONF_DIR/secrets.cred"
MASTER_KEY="$CONF_DIR/.master.key"
LIB_DIR="${ABUSE_CHECKER_LIB_DIR:-/usr/local/lib/abuse-checker}"
DROPIN_DIR="${ABUSE_CHECKER_DROPIN_DIR:-/etc/systemd/system/abuse-checker.service.d}"
RAM_DIR="${ABUSE_CHECKER_RAMDIR:-/dev/shm}"
OPENSSL_OPTS=(enc -aes-256-cbc -pbkdf2 -iter 100000 -md sha256)

systemd_version() { systemctl --version 2>/dev/null | awk 'NR==1 {print $2+0}'; }

# Which tier to use for new encryptions.
crypto_tier() {
    case "${ABUSE_CHECKER_CRYPTO:-auto}" in
        openssl|systemd) printf '%s' "$ABUSE_CHECKER_CRYPTO"; return 0 ;;
    esac
    if command -v systemd-creds >/dev/null 2>&1 && [[ -d /run/systemd/system ]] \
       && (( $(systemd_version || echo 0) >= 250 )) \
       && printf 'probe' | systemd-creds encrypt --name=probe - - >/dev/null 2>&1; then
        printf systemd
    else
        printf openssl
    fi
}

# Which store currently holds the secrets: systemd|openssl|plain|none
current_store() {
    if [[ -f "$CRED_FILE" ]]; then printf systemd
    elif [[ -f "$ENC_FILE" ]]; then printf openssl
    elif [[ -f "$SECRETS_FILE" ]]; then printf plain
    else printf none; fi
}

master_key_path() {
    if [[ -n "${CREDENTIALS_DIRECTORY:-}" && -r "$CREDENTIALS_DIRECTORY/master.key" ]]; then
        printf '%s' "$CREDENTIALS_DIRECTORY/master.key"
    else
        printf '%s' "$MASTER_KEY"
    fi
}

# Decrypt the current store to stdout (pipe only).
secrets_cat() {
    case "$(current_store)" in
        systemd) systemd-creds decrypt --name=secrets "$CRED_FILE" - ;;
        openssl) openssl "${OPENSSL_OPTS[@]}" -d -pass "file:$(master_key_path)" -in "$ENC_FILE" ;;
        plain)   cat "$SECRETS_FILE" ;;
        none)    return 1 ;;
    esac
}

# Accept only blank lines, comments and KEY=value assignments without
# command substitution, then make sure bash can parse it.
validate_secrets() {
    local f="$1" bad
    bad="$(grep -nvE "^[[:space:]]*(#.*)?$|^[[:space:]]*(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*=(\"[^\"\`]*\"|'[^']*'|[^[:space:]\"'\`\$;&|<>()]*)[[:space:]]*(#.*)?$" "$f" || true)"
    if [[ -n "$bad" ]]; then
        # shellcheck disable=SC2016
        printf 'invalid line(s) (use KEY="value" or KEY='"'"'value'"'"'; no $(...), backticks or ;):\n%s\n' \
            "$(cut -d: -f1 <<< "$bad" | sed 's/^/  line /')" >&2
        return 1
    fi
    bash -n "$f" 2>/dev/null || { echo "bash syntax check failed" >&2; return 1; }
}

secure_rm() {
    local f
    for f in "$@"; do
        [[ -e "$f" ]] || continue
        if command -v shred >/dev/null 2>&1; then shred -u -z "$f" 2>/dev/null || rm -f "$f"; else rm -f "$f"; fi
    done
}

# 0600 file on RAM for editing; never on persistent disk.
ram_tmpfile() {
    [[ -d "$RAM_DIR" && -w "$RAM_DIR" ]] || die "RAM directory $RAM_DIR not available; refusing to write secrets to disk"
    (umask 077; mktemp "$RAM_DIR/abuse-checker-secrets.XXXXXX")
}

ensure_master_key() {
    [[ -s "$MASTER_KEY" ]] && return 0
    (umask 277; openssl rand -hex 32 > "$MASTER_KEY")
    chmod 0400 "$MASTER_KEY"
    [[ $EUID -eq 0 ]] && chown root:root "$MASTER_KEY"
    info "generated new 256-bit master key $MASTER_KEY"
}

# store_secrets <plaintext-file-on-ram>: encrypt into the preferred tier,
# remove other/legacy stores, refresh the systemd drop-in.
store_secrets() {
    local plain="$1" tier tmp
    validate_secrets "$plain" || return 1
    tier="$(crypto_tier)"
    if [[ "$tier" == "systemd" ]]; then
        tmp="$(mktemp "$CONF_DIR/.secrets.cred.XXXXXX")"
        systemd-creds encrypt --name=secrets "$plain" "$tmp" 2>/dev/null || { rm -f "$tmp"; die "systemd-creds encrypt failed"; }
        chmod 0600 "$tmp"; mv -f "$tmp" "$CRED_FILE"
        rm -f "$ENC_FILE"
    else
        command -v openssl >/dev/null 2>&1 || die "openssl is required for encrypted secrets"
        ensure_master_key
        tmp="$(mktemp "$CONF_DIR/.secrets.enc.XXXXXX")"
        openssl "${OPENSSL_OPTS[@]}" -salt -pass "file:$MASTER_KEY" -in "$plain" -out "$tmp" \
            || { rm -f "$tmp"; die "openssl encryption failed"; }
        chmod 0640 "$tmp"
        if [[ $EUID -eq 0 ]] && getent group "$SERVICE_USER" >/dev/null 2>&1; then chown "root:$SERVICE_USER" "$tmp"; fi
        mv -f "$tmp" "$ENC_FILE"
        rm -f "$CRED_FILE"
    fi
    # Round-trip check before any plaintext is destroyed.
    cmp -s "$plain" <(secrets_cat 2>/dev/null) || die "verification of the encrypted store failed"
    if [[ -f "$SECRETS_FILE" ]]; then
        secure_rm "$SECRETS_FILE"
        info "removed plain-text $SECRETS_FILE"
    fi
    info "secrets encrypted ($tier tier)"
    write_dropin
}

# systemd drop-in matching the active store. Only touches the real unit
# directory when using the default /etc/abuse-checker layout.
write_dropin() {
    local store cfg
    if [[ -z "${ABUSE_CHECKER_DROPIN_DIR:-}" && "$CONF_DIR" != "/etc/abuse-checker" ]]; then return 0; fi
    store="$(current_store)"
    case "$store" in
        systemd) cfg="LoadCredentialEncrypted=secrets:$CRED_FILE" ;;
        openssl) cfg="LoadCredential=master.key:$MASTER_KEY" ;;
        plain)   cfg="EnvironmentFile=$SECRETS_FILE" ;;
        none)    cfg="" ;;
    esac
    mkdir -p "$DROPIN_DIR"
    printf '# Generated by abuse-checker; secrets store: %s\n[Service]\n%s\n' "$store" "$cfg" \
        > "$DROPIN_DIR/10-secrets.conf"
    chmod 0644 "$DROPIN_DIR/10-secrets.conf"
    if [[ -z "${ABUSE_CHECKER_DROPIN_DIR:-}" && -d /run/systemd/system ]]; then
        systemctl daemon-reload 2>/dev/null || true
    fi
}

# Load secrets into the environment (called before redaction is installed).
load_secrets() {
    set -a
    if [[ -n "${CREDENTIALS_DIRECTORY:-}" && -r "$CREDENTIALS_DIRECTORY/secrets" ]]; then
        # shellcheck source=/dev/null
        . "$CREDENTIALS_DIRECTORY/secrets"
    elif [[ -f "$ENC_FILE" ]]; then
        if [[ -r "$ENC_FILE" && -r "$(master_key_path)" ]]; then
            local dec
            dec="$(openssl "${OPENSSL_OPTS[@]}" -d -pass "file:$(master_key_path)" -in "$ENC_FILE" 2>/dev/null)" \
                || { set +a; die "cannot decrypt $ENC_FILE (wrong or missing master key?)"; }
            # shellcheck source=/dev/null
            . <(printf '%s\n' "$dec")
            unset dec
        elif [[ -z "${ABUSEIPDB_API_KEYS:-}" ]]; then
            warn "secrets are encrypted but the master key is not readable; run as root or via systemd"
        fi
    elif [[ -f "$CRED_FILE" ]]; then
        if [[ $EUID -eq 0 ]] && command -v systemd-creds >/dev/null 2>&1; then
            # shellcheck source=/dev/null
            . <(systemd-creds decrypt --name=secrets "$CRED_FILE" - 2>/dev/null) \
                || warn "cannot decrypt $CRED_FILE"
        elif [[ -z "${ABUSEIPDB_API_KEYS:-}" ]]; then
            warn "secrets are in $CRED_FILE; run as root or via systemd"
        fi
    elif [[ -r "$SECRETS_FILE" ]]; then
        if [[ -n "$(find "$SECRETS_FILE" -perm -0002 2>/dev/null)" ]]; then
            set +a; die "$SECRETS_FILE is world-writable; refusing to load it"
        fi
        # shellcheck source=/dev/null
        . "$SECRETS_FILE"
        warn "secrets are stored in plain text ($SECRETS_FILE); run 'sudo abuse-checker --encrypt-secrets'"
    fi
    set +a
}

require_admin() {
    if [[ $EUID -ne 0 && "$CONF_DIR" == "/etc/abuse-checker" ]]; then
        die "this command must be run as root (sudo abuse-checker $1)"
    fi
    [[ -d "$CONF_DIR" ]] || die "$CONF_DIR does not exist (run install.sh)"
}

# Plaintext of the current store (or the template) into a RAM file whose
# path is left in RAM_COPY (no subshell, so cleanup sees it in RAM_FILES).
open_ram_copy() {
    RAM_COPY="$(ram_tmpfile)"
    RAM_FILES+=("$RAM_COPY")
    if ! secrets_cat > "$RAM_COPY" 2>/dev/null; then
        if [[ "$(current_store)" != "none" ]]; then die "cannot decrypt the current secrets store"; fi
        if [[ -r "$CONF_DIR/secrets.conf.example" ]]; then cat "$CONF_DIR/secrets.conf.example" > "$RAM_COPY"
        else printf '# abuse-checker secrets\nABUSEIPDB_API_KEYS=""\n' > "$RAM_COPY"; fi
    fi
}

cleanup_ram() { secure_rm "${RAM_FILES[@]}"; }

cmd_edit_secrets() {
    require_admin --edit-secrets
    local ram editor before after reply
    trap cleanup_ram EXIT
    open_ram_copy; ram="$RAM_COPY"
    before="$(cksum < "$ram")"
    editor="${VISUAL:-${EDITOR:-}}"
    if [[ -z "$editor" ]]; then
        if command -v nano >/dev/null 2>&1; then editor="nano"; else editor="vi"; fi
    fi
    while true; do
        # Word splitting allows EDITOR="code --wait" style values.
        # shellcheck disable=SC2086
        $editor "$ram" || die "editor exited with an error; nothing changed"
        if validate_secrets "$ram"; then break; fi
        if [[ -t 0 ]]; then
            read -r -p "Re-open the editor to fix it? [Y/n] " reply
            [[ "$reply" =~ ^[Nn] ]] && die "aborted; nothing changed"
        else
            die "invalid configuration; nothing changed"
        fi
    done
    after="$(cksum < "$ram")"
    if [[ "$before" == "$after" && "$(current_store)" != "plain" && "$(current_store)" != "none" ]]; then
        info "no changes"
        return 0
    fi
    store_secrets "$ram"
}

# --encrypt-secrets [--from FILE]: migrate plain text into the encrypted store.
cmd_encrypt_secrets() {
    require_admin --encrypt-secrets
    local src="${1:-$SECRETS_FILE}" ram
    trap cleanup_ram EXIT
    [[ -f "$src" ]] || {
        [[ "$(current_store)" =~ ^(openssl|systemd)$ ]] && { info "secrets are already encrypted ($(current_store))"; return 0; }
        die "no plain-text secrets file found at $src"
    }
    ram="$(ram_tmpfile)"; RAM_FILES+=("$ram")
    cat "$src" > "$ram"
    store_secrets "$ram"
    [[ "$src" != "$SECRETS_FILE" && -f "$src" ]] && secure_rm "$src"
    return 0
}

# --set-secret KEY  (value read from stdin, so it never appears in argv)
cmd_set_secret() {
    local key="$1" value ram tmp
    require_admin --set-secret
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "invalid variable name: $key"
    IFS= read -r value || true
    [[ "$value" != *"'"* ]] || die "values may not contain single quotes"
    trap cleanup_ram EXIT
    open_ram_copy; ram="$RAM_COPY"
    tmp="$(ram_tmpfile)"; RAM_FILES+=("$tmp")
    AC_VAL="$value" awk -v k="$key" '
        BEGIN { line = k "='"'"'" ENVIRON["AC_VAL"] "'"'"'" }
        $0 ~ "^[[:space:]]*(export[[:space:]]+)?" k "=" { if (!done) print line; done = 1; next }
        { print }
        END { if (!done) print line }' "$ram" > "$tmp"
    cat "$tmp" > "$ram"
    store_secrets "$ram"
    info "updated $key"
}

# ---------------------------------------------------------------------------
# Built-in uninstaller
# ---------------------------------------------------------------------------
cmd_uninstall() {
    local choice="${1:-}" r="${AC_ROOT:-}" p size reply
    local conf="$r/etc/abuse-checker" state="$r/var/lib/abuse-checker"
    local -a app=("$r/usr/local/bin/abuse-checker" "$r/usr/local/lib/abuse-checker"
                  "$r/usr/local/share/doc/abuse-checker"
                  "$r/etc/systemd/system/abuse-checker.service"
                  "$r/etc/systemd/system/abuse-checker.timer"
                  "$r/etc/systemd/system/abuse-checker.service.d"
                  "$r/etc/systemd/system/abuse-checker.timer.d")
    [[ $EUID -eq 0 || -n "$r" ]] || die "run as root: sudo abuse-checker --uninstall"
    show() { for p in "$@"; do [[ -e "$p" ]] || continue; size="$(du -sh "$p" 2>/dev/null | cut -f1)"; printf '      %-55s %s\n' "$p" "$size"; done; }
    if [[ -z "$choice" ]]; then
        if [[ -t 0 || "${ABUSE_CHECKER_ASSUME_TTY:-}" == "1" ]]; then
            echo "abuse-checker uninstaller"
            echo
            echo "  [1] Remove application & systemd timer only (KEEP encrypted secrets, ips.txt, and HTML reports)"
            echo "      Removes:"
            show "${app[@]}"
            echo "  [2] Full Purge (Remove everything including /etc/abuse-checker, /var/lib/abuse-checker, and the '$SERVICE_USER' user)"
            echo "      Additionally removes:"
            show "$conf" "$state"
            echo "  [3] Cancel"
            echo
            read -r -p "Choose [1-3] (default 3): " reply || reply=3
            case "$reply" in 1) choice=keep ;; 2) choice=purge ;; *) echo "Cancelled."; return 0 ;; esac
            if [[ "$choice" == "purge" ]]; then
                read -r -p "Type 'purge' to confirm deleting secrets, state and reports: " reply || reply=""
                [[ "$reply" == "purge" ]] || { echo "Cancelled."; return 0; }
            fi
        else
            die "non-interactive uninstall needs --keep or --purge"
        fi
    fi
    if [[ -z "$r" ]] && command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        systemctl disable --now abuse-checker.timer 2>/dev/null || true
        systemctl stop abuse-checker.service 2>/dev/null || true
    fi
    for p in "${app[@]}"; do [[ -e "$p" ]] && { rm -rf "$p"; echo "removed $p"; }; done
    if [[ -z "$r" ]] && command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        systemctl daemon-reload
        systemctl reset-failed abuse-checker.service abuse-checker.timer 2>/dev/null || true
    fi
    if [[ "$choice" == "purge" ]]; then
        [[ -f "$conf/secrets.conf" ]] && secure_rm "$conf/secrets.conf"
        [[ -f "$conf/.master.key" ]] && secure_rm "$conf/.master.key"
        for p in "$conf" "$state"; do [[ -e "$p" ]] && { rm -rf "$p"; echo "removed $p"; }; done
        if [[ -z "$r" ]] && id "$SERVICE_USER" >/dev/null 2>&1; then
            userdel "$SERVICE_USER" 2>/dev/null || true
            if getent group "$SERVICE_USER" >/dev/null; then groupdel "$SERVICE_USER" 2>/dev/null || true; fi
            echo "removed system user $SERVICE_USER"
        fi
    else
        echo "kept $conf and $state"
    fi
    echo "uninstall complete"
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
setup_tmp() {
    TMPD="$(mktemp -d "${TMPDIR:-/tmp}/abuse-checker.XXXXXX")"
    trap 'rm -rf "$TMPD"' EXIT
}

acquire_lock() {
    command -v flock >/dev/null 2>&1 || return 0
    exec 9> "$STATE_DIR/.lock" || return 0
    flock -n 9 || die "another abuse-checker instance is running"
}

cmd_run() {
    local results classified newstate report today state_file count_alert suffix=""
    [[ -d "$STATE_DIR" ]] || die "state directory $STATE_DIR does not exist (run install.sh)"
    mkdir -p "$REPORT_DIR"
    acquire_lock
    state_file="$STATE_FILE"
    if $DRY_RUN; then
        state_file="$STATE_DIR/state.dryrun.json"; suffix="_dryrun"
        if [[ ! -r "$IPS_FILE" ]]; then
            IPS_FILE="$TMPD/sample_ips.txt"
            printf "%s\n" 192.0.2.1 192.0.2.10 192.0.2.11 192.0.2.12 192.0.2.13 203.0.113.5 203.0.113.9 198.51.100.0/24 > "$IPS_FILE"
        fi
        info "dry-run: using mock AbuseIPDB responses, state file $state_file"
    fi
    ensure_state "$state_file"
    results="$TMPD/results.jsonl"; classified="$TMPD/classified.json"; newstate="$TMPD/state.new"
    collect_results "$results"
    if [[ ! -s "$results" ]]; then
        info "nothing checked; state left unchanged"
        return 0
    fi
    classify "$state_file" "$results" > "$classified"
    read_targets "$IPS_FILE" 2>/dev/null | jq -R . | jq -s . > "$TMPD/targets.json"
    jq -r '.[].target' "$classified" | jq -R . | jq -s --slurpfile t "$TMPD/targets.json" '. + $t[0] | unique' > "$TMPD/targets.all"
    new_state "$state_file" "$classified" "$TMPD/targets.all" > "$newstate"
    write_atomic "$state_file" "$newstate"
    info "summary: $(summary_counts "$classified")"
    jq -r '.[] | "  \(.status)\t\(.target)\tscore=\(.score)\treports=\(.total)\tdelta=\(.delta)"' "$classified" >&2

    count_alert="$(alert_items "$classified" | jq 'length')"
    if (( count_alert == 0 )); then
        info "no NEW or ESCALATED IPs; no report or alert generated"
        prune_reports
        return 0
    fi
    today="$(date '+%Y-%m-%d')"
    report="$REPORT_DIR/report_${today}${suffix}.html"
    render_report "$classified" "$report" "$today"
    info "report written: $report ($(wc -c < "$report" | tr -d ' ') bytes)"
    if $DRY_RUN; then
        info "dry-run: notifications skipped"
        plain_summary "$classified" "[DRY-RUN] AbuseIPDB alert for $HOST_LABEL" >&2
    else
        notify_all "$classified" "$report" "AbuseIPDB alert for $HOST_LABEL: $count_alert IP(s) need attention"
    fi
    prune_reports
}

cmd_test_notify() {
    local results="$TMPD/results.jsonl" classified="$TMPD/classified.json" report
    mkdir -p "$REPORT_DIR" 2>/dev/null || true
    [[ -w "$REPORT_DIR" ]] || REPORT_DIR="$TMPD"
    DRY_RUN=true
    : > "$results"
    local t
    for t in 192.0.2.10 192.0.2.11 192.0.2.12 192.0.2.13 198.51.100.0/24; do check_target "$t" "$results"; done
    jq -s 'to_entries | map(.value + {dirty:(.value.total > 0),
        status:(if .value.total == 0 then "CLEAN" else ["NEW","ESCALATED","UNCHANGED"][.key % 3] end),
        delta:(if .key % 3 == 1 then 3 else 0 end)})' "$results" > "$classified"
    report="$REPORT_DIR/report_$(date '+%Y-%m-%d')_test.html"
    render_report "$classified" "$report" "(TEST)"
    info "test report written: $report"
    if [[ -z "${TELEGRAM_BOT_TOKEN:-}${SLACK_WEBHOOK_URLS:-}${EMAIL_TO:-}" ]]; then
        warn "no notification channels configured (TELEGRAM_*, SLACK_WEBHOOK_URLS, EMAIL_TO)"
    fi
    notify_all "$classified" "$report" "[TEST] abuse-checker notification from $HOST_LABEL"
}

cmd_status() {
    local f="$STATE_FILE"
    echo "abuse-checker v$AC_VERSION"
    echo "IP list     : $IPS_FILE ($( [[ -r "$IPS_FILE" ]] && read_targets "$IPS_FILE" 2>/dev/null | wc -l || echo 'unreadable') target(s))"
    echo "State file  : $f"
    if [[ -r "$f" ]]; then
        jq -r --argjson th "$THRESHOLD" '
            "Tracked     : \(.ips|length)",
            "Dirty       : \([.ips[] | select(.dirty)] | length)",
            "Clean       : \([.ips[] | select(.dirty|not)] | length)",
            "Last run    : \(.lastRun // "never")"' "$f"
    else
        echo "State       : (no state yet or not readable)"
    fi
    echo "Reports     : $(find "$REPORT_DIR" -maxdepth 1 -name 'report_*.html' 2>/dev/null | wc -l) file(s) in $REPORT_DIR"
    echo "API keys    : ${#API_KEYS[@]} configured"
    echo "Secrets     : $(current_store) store (new encryptions use: $(crypto_tier))"
    local c names=""
    while IFS= read -r c; do names+="$(basename "$c" .sh) "; done < <(valid_connectors 2>/dev/null)
    echo "Connectors  : ${names:-none} ($(connectors_dir))"
    if command -v systemctl >/dev/null 2>&1; then
        echo "Next run    : $(systemctl show abuse-checker.timer -p NextElapseUSecRealtime --value 2>/dev/null || echo unknown)"
        systemctl list-timers abuse-checker.timer --no-pager 2>/dev/null | sed -n '1,2p' || true
    fi
}

cmd_reset_state() {
    [[ -d "$STATE_DIR" ]] || die "state directory $STATE_DIR does not exist"
    echo '{"version":1,"lastRun":null,"ips":{}}' > "$TMPD/empty.json"
    write_atomic "$STATE_FILE" "$TMPD/empty.json"
    rm -f "$STATE_DIR/state.dryrun.json"
    if [[ $EUID -eq 0 ]] && id "$SERVICE_USER" >/dev/null 2>&1; then
        chown "$SERVICE_USER:$SERVICE_USER" "$STATE_FILE"
    fi
    info "state cleared: $STATE_FILE"
}

usage() {
    cat <<EOF
abuse-checker v$AC_VERSION - AbuseIPDB monitoring with stateful diff alerts

Usage: abuse-checker [OPTION]

  --run                 Run the daily check (default)
  --dry-run             Use mock API responses; separate state, no notifications
  --test-notify         Build a sample report and send a test alert to all channels
  --force-full-report   Alert on every currently dirty IP, ignoring the diff state
  --status              Show tracked IPs, dirty count, last run, next timer trigger
  --reset-state         Clear $STATE_DIR/state.json

Secrets & maintenance (root):
  --edit-secrets        Decrypt to RAM (/dev/shm), open \$EDITOR, validate, re-encrypt
  --encrypt-secrets     Migrate plain-text secrets.conf into the encrypted store
  --set-secret KEY      Set one variable; the value is read from stdin
  --uninstall [--keep|--purge]
                        Remove the application (menu when interactive)
  -h, --help            Show this help
  -V, --version         Show version
EOF
}

main() {
    local arg extra=""
    while (( $# )); do
        arg="$1"; shift
        case "$arg" in
            --run) MODE="run" ;;
            --dry-run) MODE="run"; DRY_RUN=true ;;
            --force-full-report) MODE="run"; FORCE_FULL=true ;;
            --test-notify) MODE="test-notify" ;;
            --status) MODE="status" ;;
            --reset-state) MODE="reset" ;;
            --edit-secrets) MODE="edit-secrets" ;;
            --encrypt-secrets) MODE="encrypt-secrets" ;;
            --from) extra="${1:?--from needs a path}"; shift ;;
            --set-secret) MODE="set-secret"; extra="${1:?--set-secret needs a variable name}"; shift ;;
            --uninstall) MODE="uninstall" ;;
            --keep|--purge) extra="${arg#--}" ;;
            --refresh-unit) MODE="refresh-unit" ;;
            -h|--help) usage; exit 0 ;;
            -V|--version) echo "$AC_VERSION"; exit 0 ;;
            *) usage >&2; exit 2 ;;
        esac
    done
    # Management commands: interactive, no secrets loaded, no output filter
    # (an editor needs the real terminal).
    case "$MODE" in
        edit-secrets) cmd_edit_secrets; return ;;
        encrypt-secrets) cmd_encrypt_secrets "$extra"; return ;;
        set-secret) cmd_set_secret "$extra"; return ;;
        uninstall) cmd_uninstall "$extra"; return ;;
        refresh-unit) write_dropin; return ;;
    esac
    load_config
    install_redaction
    require_tools
    setup_tmp
    case "$MODE" in
        run) cmd_run ;;
        test-notify) cmd_test_notify ;;
        status) cmd_status ;;
        reset) cmd_reset_state ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
