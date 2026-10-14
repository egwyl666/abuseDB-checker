#!/usr/bin/env bash
# abuse-checker - daily AbuseIPDB monitoring for a pool of IPs/CIDRs.
# Pure Bash + curl + jq + coreutils. See README.md.
set -euo pipefail
umask 027

readonly AC_VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Paths (overridable through the environment, mainly for tests)
# ---------------------------------------------------------------------------
CONF_DIR="${ABUSE_CHECKER_CONF_DIR:-/etc/abuse-checker}"
SECRETS_FILE="${ABUSE_CHECKER_SECRETS:-$CONF_DIR/secrets.conf}"
STATE_DIR="${ABUSE_CHECKER_STATE_DIR:-/var/lib/abuse-checker}"
CURL_BIN="${ABUSE_CHECKER_CURL:-curl}"
SERVICE_USER="abusechecker"

TMPD=""
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
    for v in "${ABUSEIPDB_API_KEYS:-}" "${TELEGRAM_BOT_TOKEN:-}" "${SLACK_WEBHOOK_URLS:-}" \
             "${SMTP_PASS:-}"; do
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
    if [[ -r "$SECRETS_FILE" ]]; then
        if [[ -n "$(find "$SECRETS_FILE" -perm -0002 2>/dev/null)" ]]; then
            die "$SECRETS_FILE is world-writable; refusing to load it"
        fi
        set -a
        # shellcheck source=/dev/null
        . "$SECRETS_FILE"
        set +a
    fi
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
    mapfile -t targets < <(read_targets "$IPS_FILE")
    (( ${#targets[@]} > 0 )) || die "no valid targets in $IPS_FILE"
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

send_telegram() {
    local data="$1" report="$2" title="$3" text chat cfg ok=0 fail=0
    [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_IDS:-}" ]] || return 0
    text="$(jq -r --arg title "$title" --argjson force "$FORCE_FULL" '
        def e: tostring | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;");
        def icon: {"NEW":"🔴","ESCALATED":"🟠","UNCHANGED":"🟡"}[.status] // "";
        [.[] | select(.status=="NEW" or .status=="ESCALATED" or ($force and .status=="UNCHANGED"))] as $a
        | "<b>\($title|e)</b>\n"
        + "Checked <b>\(length)</b> · New <b>\(map(select(.status=="NEW"))|length)</b> · Escalated <b>\(map(select(.status=="ESCALATED"))|length)</b>\n\n"
        + ([$a[:25][] | "\(icon) <code>\(.target|e)</code> — \(.score)% · \(.total) reports" + (if .delta > 0 then " (+\(.delta))" else "" end) + (if (.isp//"") != "" then "\n    <i>\(.isp|e)</i>" else "" end)] | join("\n"))
        + (if ($a|length) > 25 then "\n…and \(($a|length) - 25) more (see report)" else "" end)
        + "\n\n<i>\(map(select(.status=="UNCHANGED"))|length) unchanged dirty IP(s) not re-alerted.</i>"' "$data")"
    while IFS= read -r chat; do
        cfg="$(cfg_line url "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage")
$(cfg_line form-string "chat_id=$chat")
$(cfg_line form-string "parse_mode=HTML")
$(cfg_line form-string "disable_web_page_preview=true")
$(cfg_line form-string "text=$text")"
        if secure_curl "$cfg" --max-time 30 --fail -o /dev/null; then ok=$((ok+1)); else fail=$((fail+1)); warn "Telegram sendMessage to chat $chat failed"; fi
        if [[ -f "$report" ]]; then
            cfg="$(cfg_line url "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument")
$(cfg_line form-string "chat_id=$chat")
$(cfg_line form "document=@$report;type=text/html")
$(cfg_line form-string "caption=Interactive report: $(basename "$report")")"
            secure_curl "$cfg" --max-time 60 --fail -o /dev/null || { fail=$((fail+1)); warn "Telegram sendDocument to chat $chat failed"; }
        fi
    done < <(split_csv "$TELEGRAM_CHAT_IDS")
    info "Telegram: $ok chat(s) notified, $fail failure(s)"
}

send_slack() {
    local data="$1" report="$2" title="$3" payload url n=0 i=0
    [[ -n "${SLACK_WEBHOOK_URLS:-}" ]] || return 0
    payload="$TMPD/slack.json"
    jq --arg title "$title" --arg report "$(basename "$report")" --argjson force "$FORCE_FULL" '
        [.[] | select(.status=="NEW" or .status=="ESCALATED" or ($force and .status=="UNCHANGED"))] as $a
        | {text:$title, blocks:(
            [{type:"header", text:{type:"plain_text", text:$title[:150]}},
             {type:"section", fields:[
                {type:"mrkdwn", text:"*Checked:* \(length)"},
                {type:"mrkdwn", text:"*Clean:* \(map(select(.status=="CLEAN"))|length)"},
                {type:"mrkdwn", text:":red_circle: *New:* \(map(select(.status=="NEW"))|length)"},
                {type:"mrkdwn", text:":large_orange_circle: *Escalated:* \(map(select(.status=="ESCALATED"))|length)"}]},
             {type:"divider"}]
            + [$a[:20][] | {type:"section",
                text:{type:"mrkdwn", text:("*\(.status)* `\(.target)` — score *\(.score)%*, \(.total) reports" + (if .delta > 0 then " (+\(.delta))" else "" end) + (if (.isp//"") != "" then "\n_\(.isp)_ \(.country // "")" else "" end))},
                accessory:{type:"button", text:{type:"plain_text", text:"AbuseIPDB"}, url:"https://www.abuseipdb.com/check/\(.target|@uri)"}}]
            + [{type:"context", elements:[{type:"mrkdwn", text:"\(map(select(.status=="UNCHANGED"))|length) unchanged dirty IP(s) not re-alerted · full report: \($report)"}]}])}' "$data" > "$payload" \
        || { warn "Slack: failed to build payload"; return 1; }
    while IFS= read -r url; do
        i=$((i+1))
        if secure_curl "$(cfg_line url "$url")
$(cfg_line header "Content-Type: application/json")" --max-time 30 --fail -o /dev/null --data-binary "@$payload"; then
            n=$((n+1))
        else
            warn "Slack webhook #$i failed"
        fi
    done < <(split_csv "$SLACK_WEBHOOK_URLS")
    info "Slack: $n of $i webhook(s) notified"
}

send_email() {
    local data="$1" report="$2" title="$3" msg boundary rcpt cfg to_hdr
    [[ -n "${EMAIL_TO:-}" ]] || return 0
    msg="$TMPD/mail.eml"; boundary="=_ac_$(date +%s)_$$"
    to_hdr="$(split_csv "$EMAIL_TO" | paste -sd, - | sed 's/,/, /g')"
    {
        printf 'From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\n' \
            "$EMAIL_FROM" "$to_hdr" "$title" "$(date -R)"
        printf 'Content-Type: multipart/mixed; boundary="%s"\r\n\r\n' "$boundary"
        printf -- '--%s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n' "$boundary"
        plain_summary "$data" "$title" | sed 's/$/\r/'
        if [[ -f "$report" ]]; then
            printf '\r\n--%s\r\nContent-Type: text/html; charset=utf-8; name="%s"\r\n' "$boundary" "$(basename "$report")"
            printf 'Content-Disposition: attachment; filename="%s"\r\nContent-Transfer-Encoding: base64\r\n\r\n' "$(basename "$report")"
            base64 -w 76 "$report" | sed 's/$/\r/'
        fi
        printf '\r\n--%s--\r\n' "$boundary"
    } > "$msg"
    if [[ -n "${SMTP_URL:-}" ]]; then
        cfg="$(cfg_line url "$SMTP_URL")
$(cfg_line mail-from "${SMTP_FROM:-${EMAIL_FROM}}")
$(cfg_line upload-file "$msg")"
        [[ -n "${SMTP_USER:-}" ]] && cfg+=$'\n'"$(cfg_line user "${SMTP_USER}:${SMTP_PASS:-}")"
        [[ "$SMTP_URL" == smtp://* ]] && cfg+=$'\n'"ssl-reqd"
        while IFS= read -r rcpt; do cfg+=$'\n'"$(cfg_line mail-rcpt "$rcpt")"; done < <(split_csv "$EMAIL_TO")
        if secure_curl "$cfg" --max-time 60; then info "Email: sent to $to_hdr via SMTP"; else warn "Email via SMTP failed"; fi
    elif command -v sendmail >/dev/null 2>&1; then
        if sendmail -t < "$msg"; then info "Email: sent to $to_hdr via sendmail"; else warn "Email via sendmail failed"; fi
    else
        warn "EMAIL_TO is set but neither SMTP_URL nor sendmail is available"
    fi
}

notify_all() {
    send_telegram "$@" || warn "Telegram delivery error"
    send_slack "$@" || warn "Slack delivery error"
    send_email "$@" || warn "Email delivery error"
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
  -h, --help            Show this help
  -V, --version         Show version
EOF
}

main() {
    local arg
    for arg in "$@"; do
        case "$arg" in
            --run) MODE="run" ;;
            --dry-run) MODE="run"; DRY_RUN=true ;;
            --force-full-report) MODE="run"; FORCE_FULL=true ;;
            --test-notify) MODE="test-notify" ;;
            --status) MODE="status" ;;
            --reset-state) MODE="reset" ;;
            -h|--help) usage; exit 0 ;;
            -V|--version) echo "$AC_VERSION"; exit 0 ;;
            *) usage >&2; exit 2 ;;
        esac
    done
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
