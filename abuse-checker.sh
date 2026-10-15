#!/usr/bin/env bash
# abuse-checker - daily AbuseIPDB monitoring for a pool of IPs/CIDRs.
# Pure Bash + curl + jq + coreutils. See README.md.
set -euo pipefail
umask 027

readonly AC_VERSION="1.5.0"
# Upstream repository used by --check-update / --update (override with
# REPO_SLUG / REPO_BRANCH in the secrets store).
readonly DEFAULT_REPO_SLUG="egwyl666/abuseDB-checker"
readonly DEFAULT_REPO_BRANCH="main"

# ---------------------------------------------------------------------------
# Paths (overridable through the environment, mainly for tests)
# ---------------------------------------------------------------------------
CONF_DIR="${ABUSE_CHECKER_CONF_DIR:-/etc/abuse-checker}"
SECRETS_FILE="${ABUSE_CHECKER_SECRETS:-$CONF_DIR/secrets.conf}"
STATE_DIR="${ABUSE_CHECKER_STATE_DIR:-/var/lib/abuse-checker}"
CURL_BIN="${ABUSE_CHECKER_CURL:-curl}"
IPS_FILE="${IPS_FILE:-$CONF_DIR/ips.txt}"
STATE_FILE="${STATE_FILE:-$STATE_DIR/state.json}"
SERVICE_USER="abusechecker"

TMPD=""
RAM_FILES=()
IP_ARGS=()
IP_COMMENT=""
UPGRADE_OS=false
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
    local -a miss=()
    mapfile -t miss < <(for t in jq awk sed date mktemp flock; do have_tool "$t" || echo "$t"; done)
    command -v "$CURL_BIN" >/dev/null 2>&1 || miss+=(curl)
    (( ${#miss[@]} == 0 )) && return 0
    # Root fallback: install what is missing instead of failing the run.
    if [[ "${AUTO_INSTALL_DEPS:-true}" != "false" ]] && can_manage_packages && install_missing_deps >/dev/null; then
        info "installed missing dependencies: ${miss[*]}"
        return 0
    fi
    die "missing dependencies: ${miss[*]} (run: sudo abuse-checker --doctor)"
}

# ---------------------------------------------------------------------------
# Target parsing and CIDR handling
# ---------------------------------------------------------------------------
is_ipv4() {
    local ip="$1" o
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
}
# Strict-enough IPv6 check: hex groups, at most one "::", optional
# trailing dotted IPv4 (e.g. ::ffff:192.0.2.1).
is_ipv6() {
    local a="$1" v4="" g n=0
    [[ "$a" == *:* && "$a" =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
    if [[ "$a" == *.* ]]; then v4="${a##*:}"; is_ipv4 "$v4" || return 1; a="${a%:*}:0:0"; fi
    [[ "$a" != *:::* && "$(grep -o '::' <<< "$a" | wc -l)" -le 1 ]] || return 1
    [[ "$a" =~ ^:[^:] || "$a" =~ [^:]:$ ]] && return 1
    IFS=':' read -r -a _g <<< "$a"
    for g in "${_g[@]}"; do
        [[ -z "$g" ]] && continue
        [[ "$g" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
        n=$((n + 1))
    done
    if [[ "$a" == *::* ]]; then (( n <= 7 )); else (( n == 8 )); fi
}

# valid_target "IP" or "IP/prefix"
valid_target() {
    local t="$1" addr="${1%%/*}" prefix=""
    [[ "$t" == */* ]] && prefix="${t#*/}"
    if is_ipv4 "$addr"; then
        [[ -z "$prefix" ]] || { [[ "$prefix" =~ ^[0-9]{1,2}$ ]] && (( 10#$prefix <= 32 )); }
    elif is_ipv6 "$addr"; then
        [[ -z "$prefix" ]] || { [[ "$prefix" =~ ^[0-9]{1,3}$ ]] && (( 10#$prefix <= 128 )); }
    else
        return 1
    fi
}

# Print one valid target per line (comments and blanks ignored).
read_targets() {
    local file="$1" line
    [[ -r "$file" ]] || die "IP list not readable: $file"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="$(trim "$line")"
        [[ -z "$line" ]] && continue
        if ! valid_target "$line"; then
            if [[ "$line" == */* ]]; then warn "skipping invalid CIDR: $line"; else warn "skipping invalid entry: $line"; fi
            continue
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

# Shared jq helpers (also used by the HTML report and the connectors).
#   catname : AbuseIPDB category id -> name (https://www.abuseipdb.com/categories)
#   catlist : "[SSH, Brute-Force]" for an entry, or ""
#   why     : one-line reason, max 120 chars: latest report comment for an
#             IP, or the worst sub-hosts for a CIDR
# shellcheck disable=SC2016
JQ_LIB='
def catname: {"1":"DNS Compromise","2":"DNS Poisoning","3":"Fraud Orders","4":"DDoS Attack",
    "5":"FTP Brute-Force","6":"Ping of Death","7":"Phishing","8":"Fraud VoIP","9":"Open Proxy",
    "10":"Web Spam","11":"Email Spam","12":"Blog Spam","13":"VPN IP","14":"Port Scan",
    "15":"Hacking","16":"SQL Injection","17":"Spoofing","18":"Brute-Force","19":"Bad Web Bot",
    "20":"Exploited Host","21":"Web App Attack","22":"SSH","23":"IoT Targeted"}[tostring]
    // "Category \(.)";
def catlist: (.topCategories // []) | if length > 0 then "[" + join(", ") + "]" else "" end;
def clip($n): if length > $n then .[:$n] + "…" else . end;
def why: if .kind == "cidr" then
        ((.hosts // [])[:3] | map("\(.ipAddress) (\(.abuseConfidenceScore // 0)%)")
         | if length > 0 then "worst hosts: " + join(", ") else "" end)
    else ((.reports // [])[0].comment // "") | gsub("[\\r\\n\\t]+"; " ") | gsub("^ +| +$"; "") | clip(120) end;
'

# Normalize an API response into one result object (jq programs, not shell).
# shellcheck disable=SC2016
norm_check='.data | {target:$t, kind:"ip", score:(.abuseConfidenceScore // 0),
    total:(.totalReports // 0), last:(.lastReportedAt // null), isp:(.isp // ""),
    domain:(.domain // ""), country:(.countryCode // ""),
    usage:(.usageType // ""), hostnames:((.hostnames // []) | join(", ")),
    distinctUsers:(.numDistinctUsers // 0),
    reports:((.reports // []) | sort_by(.reportedAt // "") | reverse | .[:10]
        | map({reportedAt, comment:((.comment // "") | .[:1000]),
               categories:((.categories // []) | map(catname)),
               reporterCountryCode:(.reporterCountryCode // "")})),
    topCategories:([(.reports // [])[] | (.categories // [])[]]
        | group_by(.) | map({c:.[0], n:length}) | sort_by(-.n, .c) | map(.c | catname))}'
# shellcheck disable=SC2016
norm_block='.data as $d | ($d.reportedAddress // []) as $r | {target:$t, kind:"cidr",
    score:([$r[].abuseConfidenceScore] | max // 0),
    total:([$r[].numReports] | add // 0),
    last:([$r[].mostRecentReport | select(. != null)] | max),
    isp:("Subnet: \($r | length) of \($d.numPossibleHosts // "?") hosts reported"),
    domain:"", country:([$r[].countryCode | select(. != null)] | unique | join(",")),
    reportedHosts:($r | length),
    hosts:($r | sort_by(-(.abuseConfidenceScore // 0), -(.numReports // 0)) | .[:25]
        | map({ipAddress, numReports:(.numReports // 0), abuseConfidenceScore:(.abuseConfidenceScore // 0),
               mostRecentReport, countryCode:(.countryCode // "")}))}'

# Deterministic mock response used by --dry-run / --test-notify. Dirty IPs
# carry realistic verbose .reports[] (categories + log comments).
mock_response() {
    local endpoint="$1" target="$2" h ts
    h=$(printf '%s' "$target" | cksum | awk '{print $1 % 4}')
    ts="2026-01-15T08:30:00+00:00"  # fixed so repeated dry-runs are stable
    if [[ "$endpoint" == "check" ]]; then
        jq -n --arg ip "$target" --arg ts "$ts" --argjson h "$h" '
            [ {s:0,  n:0,  isp:"Example Clean ISP",  dom:"clean.example", cc:"DE", u:"Data Center/Web Hosting/Transit", r:[]},
              {s:12, n:2,  isp:"Mock Hosting LLC",   dom:"mock.example",  cc:"NL", u:"Data Center/Web Hosting/Transit",
               r:[{c:[14],     m:"Port scan: 1,024 TCP SYN probes in 60s (ports 22,23,80,443,3389)", cc:"US"}]},
              {s:87, n:41, isp:"Bad Actor Networks", dom:"bad.example",   cc:"US", u:"Data Center/Web Hosting/Transit",
               r:[{c:[18,22],  m:"SSH brute-force login attempt from user root", cc:"DE"},
                  {c:[18,22],  m:"Failed password for invalid user admin from 192.0.2.12 port 51234 ssh2", cc:"FR"},
                  {c:[21,15],  m:"GET /wp-login.php?action=register - WordPress login abuse", cc:"GB"}]},
              {s:45, n:7,  isp:"Shared VPS Ltd",     dom:"vps.example",   cc:"FR", u:"Commercial",
               r:[{c:[11,10],  m:"Spam relay: 312 messages rejected by RBL", cc:"CA"},
                  {c:[19],     m:"Aggressive crawler ignoring robots.txt", cc:"US"}]} ][$h] as $m
            | {data:{ipAddress:$ip, abuseConfidenceScore:$m.s, totalReports:$m.n,
                     lastReportedAt:(if $m.n > 0 then $ts else null end),
                     isp:$m.isp, domain:$m.dom, countryCode:$m.cc, usageType:$m.u,
                     hostnames:(if $m.n > 0 then ["host-\($ip | gsub("[.:]"; "-")).\($m.dom)"] else [] end),
                     numDistinctUsers:($m.r | length),
                     reports:[$m.r | to_entries[] | {reportedAt:"2026-01-1\(5 - .key)T0\(8 - .key):30:00+00:00",
                         comment:.value.m, categories:.value.c, reporterId:(1000 + .key),
                         reporterCountryCode:.value.cc, reporterCountryName:""}]}}'
    else
        jq -n --arg n "$target" --arg ts "$ts" '{data:{networkAddress:($n|split("/")[0]),numPossibleHosts:256,
            reportedAddress:[
              {ipAddress:"198.51.100.7",  numReports:3,  mostRecentReport:$ts, abuseConfidenceScore:33, countryCode:"GB"},
              {ipAddress:"198.51.100.42", numReports:19, mostRecentReport:$ts, abuseConfidenceScore:76, countryCode:"GB"},
              {ipAddress:"198.51.100.99", numReports:1,  mostRecentReport:$ts, abuseConfidenceScore:4,  countryCode:"GB"}]}}'
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
        jq -c --arg t "$target" "$JQ_LIB $filter" "$body" >> "$results"
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
    rows="$(jq -r "$JQ_LIB"'
        def order: {"NEW":0,"ESCALATED":1,"UNCHANGED":2,"ERROR":3,"CLEAN":4}[.status];
        def sc: if .score >= 75 then "s-hi" elif .score >= 25 then "s-md" elif .score > 0 then "s-lo" else "s-0" end;
        def hsc: if . >= 75 then "s-hi" elif . >= 25 then "s-md" elif . > 0 then "s-lo" else "s-0" end;
        def ts: (. // "-") | sub("T"; " ") | sub("(\\+00:00|Z)$"; "") | @html;
        def cbadges: map("<span class=\"cat\">\(@html)</span>") | join(" ");
        def ipdetail:
            "<div class=\"meta\"><span><b>Usage type:</b> \((.usage // "") | if . == "" then "-" else @html end)</span>"
            + "<span><b>Hostnames:</b> \((.hostnames // "") | if . == "" then "-" else @html end)</span>"
            + "<span><b>Distinct reporters:</b> \(.distinctUsers // 0)</span></div>"
            + "<table class=\"sub\"><thead><tr><th>Timestamp (UTC)</th><th>Categories</th><th>Reporter</th><th>Comment / log snippet</th></tr></thead><tbody>"
            + ([.reports[] | "<tr><td class=\"m nw\">\(.reportedAt | ts)</td><td>\(.categories | cbadges)</td>"
                + "<td>\((.reporterCountryCode // "") | if . == "" then "-" else @html end)</td>"
                + "<td><pre>\((.comment // "") | if . == "" then "(no comment)" else @html end)</pre></td></tr>"] | join(""))
            + "</tbody></table>";
        def cidrdetail:
            "<div class=\"meta\"><span><b>Reported hosts in block:</b> \(.reportedHosts // (.hosts | length))</span>"
            + (if (.reportedHosts // 0) > (.hosts | length) then "<span>(showing the top \(.hosts | length) by score)</span>" else "" end) + "</div>"
            + "<table class=\"sub\"><thead><tr><th>IP</th><th>Score</th><th>Reports</th><th>Last reported (UTC)</th><th>Country</th><th></th></tr></thead><tbody>"
            + ([.hosts[] | "<tr><td class=\"m\">\(.ipAddress | @html)</td>"
                + "<td><span class=\"sc \(.abuseConfidenceScore | hsc)\">\(.abuseConfidenceScore)%</span></td>"
                + "<td>\(.numReports)</td><td class=\"m nw\">\(.mostRecentReport | ts)</td>"
                + "<td>\((.countryCode // "") | @html)</td>"
                + "<td><a class=\"btn\" target=\"_blank\" rel=\"noopener\" href=\"https://www.abuseipdb.com/check/\(.ipAddress | @uri)\">AbuseIPDB</a></td></tr>"] | join(""))
            + "</tbody></table>";
        sort_by(order, -.score)[] |
        (if .status == "CLEAN" or .status == "ERROR" then 0
         elif .kind == "cidr" then ((.hosts // []) | length) else ((.reports // []) | length) end) as $nd
        | "<tr class=\"r\" data-s=\"\(order)\"><td><span class=\"b b-\(.status|ascii_downcase)\">\(.status)</span></td>"
        + "<td class=\"m\">\(.target|@html)</td>"
        + "<td data-v=\"\(.score)\"><span class=\"sc \(sc)\">\(.score)%</span></td>"
        + "<td data-v=\"\(.total)\">\(.total)"
        + (if .delta > 0 then " <span class=\"d\">+\(.delta)</span>" elif .delta < 0 then " <span class=\"dn\">\(.delta)</span>" else "" end) + "</td>"
        + "<td>\((.topCategories // [])[:3] | cbadges)\(if ((.topCategories // []) | length) > 3 then " <small>+\((.topCategories | length) - 3)</small>" else "" end)</td>"
        + "<td data-v=\"\(if .kind == "cidr" then (.reportedHosts // 0) else (.distinctUsers // 0) end)\">"
        + (if .kind == "cidr" then "\(.reportedHosts // 0) <small>hosts</small>" elif (.distinctUsers // 0) > 0 then "\(.distinctUsers)" else "-" end) + "</td>"
        + "<td>\((.isp // "") | @html)" + (if (.domain // "") != "" then "<br><small>\(.domain|@html)</small>" else "" end)
        + (if .error then "<br><small class=\"err\">\(.error|@html)</small>" else "" end) + "</td>"
        + "<td>\((.country // "") | @html)</td>"
        + "<td data-v=\"\(.last // "")\">\((.last // "-") | sub("T"; " ") | sub("\\+00:00$"; " UTC") | @html)</td>"
        + "<td><a class=\"btn\" target=\"_blank\" rel=\"noopener\" href=\"https://www.abuseipdb.com/check/\(.target|@uri)\">AbuseIPDB</a></td></tr>"
        + (if $nd > 0 then
            "<tr class=\"dr\"><td colspan=\"10\"><details><summary>"
            + (if .kind == "cidr" then "View \($nd) reported host(s)" else "View \($nd) report detail(s)" end)
            + "</summary>" + (if .kind == "cidr" then cidrdetail else ipdetail end) + "</details></td></tr>"
           else "" end)
    ' "$data")"
    local upd_html=""
    # (patsub_replacement: a bare & in the replacement means "the match")
    [[ -n "${UPDATE_NOTICE:-}" ]] && upd_html="<div class=\"upd\">${UPDATE_NOTICE//>/\&gt;}</div>"
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
.bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}.bar input{margin:0;flex:1}
#xa{padding:8px 12px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);cursor:pointer}
.cat{display:inline-block;padding:1px 6px;margin:1px 0;border-radius:4px;font-size:11px;background:#e0e7ff;color:#3730a3;white-space:nowrap}
tr.dr>td{padding:0 10px 8px;border-bottom:1px solid var(--line)}details summary{cursor:pointer;color:#2563eb;font-size:12px;padding:4px 0}
.meta{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;margin:6px 0}
table.sub{min-width:0;font-size:12px;background:var(--bg);border-radius:6px}table.sub th{cursor:default}table.sub th:after{content:""}
pre{margin:0;white-space:pre-wrap;word-break:break-word;font:12px/1.4 ui-monospace,Menlo,Consolas,monospace}.nw{white-space:nowrap}
.upd{margin-top:12px;padding:8px 12px;border-radius:8px;background:#fef3c7;color:#92400e;font-size:13px}
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
<div class="bar"><input id="q" type="search" placeholder="Filter by IP, ISP, category, comment..."><button id="xa" type="button">Expand all</button></div>
<div class="wrap"><table id="t"><thead><tr>
<th>Status</th><th>IP / Subnet</th><th>Abuse score</th><th>Reports (+delta)</th><th>Top categories</th><th>Distinct reporters</th><th>ISP / Domain</th><th>Country</th><th>Last reported</th><th>Link</th>
</tr></thead><tbody>
${rows}
</tbody></table></div>
${upd_html}
<footer>${unch} unchanged dirty IP(s) were already known and not re-alerted. abuse-checker v${AC_VERSION}</footer>
<script>
(function(){var t=document.getElementById('t'),b=t.tBodies[0],q=document.getElementById('q'),xa=document.getElementById('xa');
var rows=[].slice.call(b.querySelectorAll('tr.r'));rows.forEach(function(r){var n=r.nextElementSibling;r._d=(n&&n.className==='dr')?n:null});
q.oninput=function(){var v=q.value.toLowerCase();rows.forEach(function(r){var s=(r.textContent+(r._d?r._d.textContent:'')).toLowerCase().indexOf(v)>-1?'':'none';r.style.display=s;if(r._d)r._d.style.display=s})};
var open=false;xa.onclick=function(){open=!open;[].forEach.call(b.querySelectorAll('details'),function(d){d.open=open});xa.textContent=open?'Collapse all':'Expand all'};
[].forEach.call(t.tHead.rows[0].cells,function(h,i){var asc=true;h.onclick=function(){
function k(r){var c=r.cells[i];if(i===0)return +r.getAttribute('data-s');var v=c.getAttribute('data-v');if(v!==null){return isNaN(v)||v===''?v:+v}return c.textContent.toLowerCase()}
rows.sort(function(x,y){var a=k(x),c=k(y);return (a>c?1:a<c?-1:0)*(asc?1:-1)});asc=!asc;rows.forEach(function(r){b.appendChild(r);if(r._d)b.appendChild(r._d)})}})})();
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
    jq -r --arg title "$title" --argjson force "$FORCE_FULL" "$JQ_LIB"'
        def item: "  [\(.status)] \(.target)  score \(.score)%  reports \(.total)" + (if .delta > 0 then " (+\(.delta))" else "" end) + (if (.isp//"") != "" then "  \(.isp)" else "" end)
            + (if catlist != "" then "\n      Categories: \(catlist)" else "" end)
            + (if why != "" then "\n      Why: \(why)" else "" end);
        "\($title)",
        "Checked: \(length) | Clean: \(map(select(.status=="CLEAN"))|length) | New: \(map(select(.status=="NEW"))|length) | Escalated: \(map(select(.status=="ESCALATED"))|length) | Errors: \(map(select(.status=="ERROR"))|length)",
        "",
        (.[] | select(.status=="NEW" or .status=="ESCALATED" or ($force and .status=="UNCHANGED")) | item),
        "",
        "\(map(select(.status=="UNCHANGED"))|length) unchanged dirty IP(s) not re-alerted."' "$data"
    [[ -z "${UPDATE_NOTICE:-}" ]] || printf '\n%s\n' "$UPDATE_NOTICE"
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
                  "$r/etc/systemd/system/abuse-checker-watchdog.service"
                  "$r/etc/systemd/system/abuse-checker-watchdog.timer"
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
        systemctl disable --now abuse-checker.timer abuse-checker-watchdog.timer 2>/dev/null || true
        systemctl stop abuse-checker.service 2>/dev/null || true
    fi
    for p in "${app[@]}"; do [[ -e "$p" ]] && { rm -rf "$p"; echo "removed $p"; }; done
    if [[ -z "$r" ]] && command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        systemctl daemon-reload
        systemctl reset-failed abuse-checker.service abuse-checker.timer abuse-checker-watchdog.service 2>/dev/null || true
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
# Self-update from GitHub
# ---------------------------------------------------------------------------
UPDATE_NOTICE=""

repo_slug()   { printf '%s' "${REPO_SLUG:-$DEFAULT_REPO_SLUG}"; }
repo_branch() { printf '%s' "${REPO_BRANCH:-$DEFAULT_REPO_BRANCH}"; }
raw_url()     { printf '%s' "${ABUSE_CHECKER_GITHUB_RAW:-https://raw.githubusercontent.com/$(repo_slug)/$(repo_branch)}/abuse-checker.sh"; }
archive_url() { printf '%s' "${ABUSE_CHECKER_GITHUB_ARCHIVE:-https://github.com/$(repo_slug)/archive/refs/heads/$(repo_branch).tar.gz}"; }

# version_gt A B -> true when A is a newer version than B
version_gt() { [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" == "$1" ]]; }

# Extract AC_VERSION from a script file.
script_version() { sed -n 's/^readonly AC_VERSION="\([0-9][0-9A-Za-z.+-]*\)"$/\1/p' "$1" | head -n1; }

# Fetch the remote version (prints it). Public URL, but still sent via stdin.
fetch_remote_version() {
    local out="$1/remote-abuse-checker.sh" code ver
    code="$(secure_curl "$(cfg_line url "$(raw_url)")" --location --max-time 30 -o "$out" -w '%{http_code}')" || code="000"
    # file:// mirrors report 000 on success.
    [[ "$code" == "200" || ( "$code" == "000" && "$(raw_url)" == file://* && -s "$out" ) ]] \
        || { warn "update check failed: HTTP $code from $(raw_url)"; return 1; }
    ver="$(script_version "$out")"
    [[ -n "$ver" ]] || { warn "update check: no AC_VERSION in remote script"; return 1; }
    printf '%s' "$ver"
}

# Cached once-a-day check used by scheduled runs. Prints the latest version.
cached_remote_version() {
    local stamp="$STATE_DIR/update-check.json" now ver="" dir
    now="$(date +%s)"
    if [[ -r "$stamp" ]] && (( now - $(jq -r '.checkedAt // 0' "$stamp" 2>/dev/null || echo 0) < 86400 )); then
        jq -r '.latest // empty' "$stamp" 2>/dev/null
        return 0
    fi
    dir="$(mktemp -d "${TMPDIR:-/tmp}/abuse-checker-upd.XXXXXX")"
    ver="$(fetch_remote_version "$dir")" || ver=""
    rm -rf "$dir"
    if [[ -n "$ver" && -w "$STATE_DIR" ]]; then
        jq -n --argjson t "$now" --arg v "$ver" '{checkedAt:$t, latest:$v}' > "$stamp.tmp" && mv -f "$stamp.tmp" "$stamp"
        if [[ $EUID -eq 0 ]] && id "$SERVICE_USER" >/dev/null 2>&1; then chown "$SERVICE_USER:$SERVICE_USER" "$stamp" 2>/dev/null || true; fi
    fi
    printf '%s' "$ver"
}

# AUTO_UPDATE=notify during --run: log + banner in report and alerts.
update_notice_check() {
    local latest
    case "${AUTO_UPDATE:-notify}" in
        false|no|off|0) return 0 ;;
    esac
    latest="$(cached_remote_version)" || return 0
    if [[ -n "$latest" ]] && version_gt "$latest" "$AC_VERSION"; then
        # shellcheck disable=SC2089,SC2090  # plain message text, not a command
        UPDATE_NOTICE="Update available: v$latest -> Run 'sudo abuse-checker --update'"
        # shellcheck disable=SC2090
        export UPDATE_NOTICE
        info "$UPDATE_NOTICE (installed v$AC_VERSION)"
    fi
    return 0
}

cmd_check_update() {
    local dir latest
    dir="$(mktemp -d "${TMPDIR:-/tmp}/abuse-checker-upd.XXXXXX")"
    latest="$(fetch_remote_version "$dir")" || { rm -rf "$dir"; die "could not determine the latest version"; }
    rm -rf "$dir"
    echo "Installed : v$AC_VERSION"
    echo "Latest    : v$latest ($(repo_slug)@$(repo_branch))"
    if version_gt "$latest" "$AC_VERSION"; then
        echo "Update available -> run: sudo abuse-checker --update"
    else
        echo "Up to date."
    fi
}

# cmd_update [force]: download, verify everything, then run install.sh.
cmd_update() {
    local force="${1:-}" dir src f ver
    if [[ $EUID -ne 0 && -z "${ABUSE_CHECKER_UPDATE_INSTALLER:-}" ]]; then
        die "run as root: sudo abuse-checker --update"
    fi
    command -v tar >/dev/null 2>&1 || die "tar is required for updates"
    dir="$(mktemp -d "${TMPDIR:-/tmp}/abuse-checker-upd.XXXXXX")"
    chmod 0700 "$dir"
    # shellcheck disable=SC2064
    trap "rm -rf '$dir'" EXIT
    info "downloading $(archive_url)"
    secure_curl "$(cfg_line url "$(archive_url)")" --fail --location --max-time 120 -o "$dir/src.tar.gz" \
        || die "download failed"
    tar -xzf "$dir/src.tar.gz" -C "$dir" 2>/dev/null || die "downloaded archive is not a valid tarball; nothing changed"
    src="$(find "$dir" -mindepth 2 -maxdepth 2 -name abuse-checker.sh -printf '%h\n' | head -n1)"
    [[ -n "$src" && -f "$src/install.sh" ]] || die "archive does not contain abuse-checker.sh/install.sh; nothing changed"
    for f in "$src/abuse-checker.sh" "$src/install.sh" "$src"/connectors/*.sh; do
        [[ -f "$f" ]] || continue
        bash -n "$f" 2>/dev/null || die "downloaded $(basename "$f") fails 'bash -n'; update rejected, installed version untouched"
    done
    ver="$(script_version "$src/abuse-checker.sh")"
    [[ -n "$ver" ]] || die "downloaded abuse-checker.sh has no AC_VERSION; update rejected"
    if [[ "$force" != "force" ]] && ! version_gt "$ver" "$AC_VERSION"; then
        info "already up to date (installed v$AC_VERSION, remote v$ver)"
        return 0
    fi
    info "verified v$ver; installing (secrets, ips.txt and state are kept)"
    if [[ -n "${ABUSE_CHECKER_UPDATE_INSTALLER:-}" ]]; then
        "$ABUSE_CHECKER_UPDATE_INSTALLER" "$src" </dev/null || die "installer failed"
    else
        bash "$src/install.sh" --no-wizard </dev/null || die "install.sh failed"
    fi
    [[ -w "$STATE_DIR" ]] && rm -f "$STATE_DIR/update-check.json"
    info "updated v$AC_VERSION -> v$ver"
}

# --auto-update: run as root by ExecStartPre=+ before each scheduled check.
# Only acts when AUTO_UPDATE=true; never fails the service.
cmd_auto_update() {
    local latest
    # Runs as root (ExecStartPre=+): repair missing dependencies first.
    if [[ -n "$(missing_tools)" ]]; then install_missing_deps >/dev/null || warn "could not install missing dependencies"; fi
    [[ "${AUTO_UPDATE:-notify}" == "true" ]] || return 0
    latest="$(cached_remote_version)" || return 0
    if [[ -n "$latest" ]] && version_gt "$latest" "$AC_VERSION"; then
        info "AUTO_UPDATE=true: updating v$AC_VERSION -> v$latest"
        ( cmd_update ) || warn "automatic update failed; continuing with v$AC_VERSION"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# IP / CIDR pool management (--list-ips, --add-ip, --del-ip, --edit-ips)
# ---------------------------------------------------------------------------
# Entry part of an ips.txt line (comment stripped, trimmed).
line_entry() { local l="${1%%#*}"; trim "$l"; }
# Inline comment of an ips.txt line (without '#').
line_comment() { [[ "$1" == *"#"* ]] || return 0; trim "${1#*#}"; }

# Write $2 over ips.txt ($1) atomically, keeping 0644 root:abusechecker.
replace_ips_file() {
    local dest="$1" src="$2" tmp
    tmp="$(mktemp "$(dirname "$dest")/.ips.XXXXXX")"
    cat "$src" > "$tmp"
    chmod 0644 "$tmp"
    if [[ -e "$dest" ]]; then
        chown --reference="$dest" "$tmp" 2>/dev/null || true
    elif [[ $EUID -eq 0 ]] && getent group "$SERVICE_USER" >/dev/null 2>&1; then
        chown "root:$SERVICE_USER" "$tmp"
    fi
    mv -f "$tmp" "$dest"
}

cmd_list_ips() {
    local f="$IPS_FILE" n=0 line entry comment status state="$STATE_FILE"
    [[ -r "$f" ]] || die "IP list not readable: $f"
    [[ -r "$state" ]] || state=/dev/null
    printf '%-4s %-28s %-18s %s\n' "#" "IP / SUBNET" "STATUS" "COMMENT"
    while IFS= read -r line || [[ -n "$line" ]]; do
        entry="$(line_entry "$line")"
        [[ -z "$entry" ]] && continue
        comment="$(line_comment "$line")"
        n=$((n + 1))
        if ! valid_target "$entry"; then
            status="INVALID"
        else
            status="$(jq -r --arg k "$entry" '
                (.ips // {})[$k] as $e
                | if $e == null then "UNCHECKED"
                  elif $e.dirty then "DIRTY (\($e.score)%)"
                  else "CLEAN" end' "$state" 2>/dev/null)"
            [[ -n "$status" ]] || status="UNCHECKED"
        fi
        printf '%-4s %-28s %-18s %s\n' "$n" "$entry" "$status" "$comment"
    done < "$f"
    (( n > 0 )) || echo "(no entries)"
    echo
    echo "$n entr$( ((n == 1)) && echo y || echo ies) in $f"
}

# --add-ip IP [IP...] [--comment TEXT]: all-or-nothing validation.
cmd_add_ip() {
    local comment="$1"; shift
    local t added=0 tmp
    local -a bad=() new=() existing=()
    require_admin --add-ip
    (( $# > 0 )) || die "usage: abuse-checker --add-ip <IP_OR_CIDR> [...] [--comment \"text\"]"
    comment="${comment//$'\n'/ }"
    [[ -f "$IPS_FILE" ]] || : > "$IPS_FILE"
    mapfile -t existing < <(while IFS= read -r l || [[ -n "$l" ]]; do line_entry "$l"; echo; done < "$IPS_FILE" | sed '/^$/d' | tr 'A-F' 'a-f')
    for t in "$@"; do
        t="$(trim "$t")"
        valid_target "$t" || { bad+=("$t"); continue; }
        local lt; lt="$(tr 'A-F' 'a-f' <<< "$t")"
        if printf '%s\n' "${existing[@]}" "${new[@]}" | tr 'A-F' 'a-f' | grep -qxF -- "$lt"; then
            echo "skip: $t is already in $IPS_FILE"
            continue
        fi
        new+=("$t")
    done
    if (( ${#bad[@]} > 0 )); then
        printf 'error: invalid IP/CIDR: %s\n' "${bad[@]}" >&2
        echo "nothing changed (expected IPv4, IPv6, or CIDR such as 203.0.113.0/24)" >&2
        return 1
    fi
    (( ${#new[@]} > 0 )) || { echo "nothing to add"; return 0; }
    tmp="$(mktemp "${TMPDIR:-/tmp}/abuse-checker-ips.XXXXXX")"
    cat "$IPS_FILE" > "$tmp"
    [[ -s "$tmp" && "$(tail -c1 "$tmp")" != "" ]] && echo >> "$tmp"
    for t in "${new[@]}"; do
        if [[ -n "$comment" ]]; then printf '%-22s # %s\n' "$t" "$comment" >> "$tmp"; else printf '%s\n' "$t" >> "$tmp"; fi
        echo "added: $t"; added=$((added + 1))
    done
    replace_ips_file "$IPS_FILE" "$tmp"; rm -f "$tmp"
    echo "$added entr$( ((added == 1)) && echo y || echo ies) added to $IPS_FILE"
}

# --del-ip IP [IP...]: remove from ips.txt and from state.json.
cmd_del_ip() {
    local t tmp sf removed=0
    local -a want=()
    require_admin --del-ip
    (( $# > 0 )) || die "usage: abuse-checker --del-ip <IP_OR_CIDR> [...]"
    [[ -f "$IPS_FILE" ]] || die "IP list not found: $IPS_FILE"
    for t in "$@"; do want+=("$(trim "$t" | tr 'A-F' 'a-f')"); done
    tmp="$(mktemp "${TMPDIR:-/tmp}/abuse-checker-ips.XXXXXX")"
    local line e found=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        e="$(line_entry "$line" | tr 'A-F' 'a-f')"
        if [[ -n "$e" ]] && printf '%s\n' "${want[@]}" | grep -qxF -- "$e"; then
            found+="$e"$'\n'; removed=$((removed + 1)); continue
        fi
        printf '%s\n' "$line" >> "$tmp"
    done < "$IPS_FILE"
    [[ -e "$tmp" ]] || : > "$tmp"
    for t in "${want[@]}"; do
        if grep -qxF -- "$t" <<< "$found"; then echo "removed: $t"; else echo "not found: $t"; fi
    done
    (( removed > 0 )) && replace_ips_file "$IPS_FILE" "$tmp"
    rm -f "$tmp"
    # Drop state for the removed targets right away (case-insensitive keys).
    for sf in "$STATE_FILE" "$STATE_DIR/state.dryrun.json"; do
        [[ -f "$sf" ]] || continue
        tmp="$(mktemp "$(dirname "$sf")/.state.XXXXXX")"
        if printf '%s\n' "${want[@]}" | jq -R . | jq -s . > "$tmp.keys" \
           && jq --slurpfile k "$tmp.keys" '.ips |= with_entries(select((.key | ascii_downcase) as $x | $k[0] | index($x) | not))' "$sf" > "$tmp"; then
            chmod 0640 "$tmp"; chown --reference="$sf" "$tmp" 2>/dev/null || true
            mv -f "$tmp" "$sf"
        else
            rm -f "$tmp"; warn "could not update $sf"
        fi
        rm -f "$tmp.keys"
    done
    echo "$removed entr$( ((removed == 1)) && echo y || echo ies) removed"
    (( removed > 0 ))
}

pick_editor() {
    local e="${VISUAL:-${EDITOR:-}}"
    if [[ -z "$e" ]]; then if command -v nano >/dev/null 2>&1; then e="nano"; else e="vi"; fi; fi
    printf '%s' "$e"
}

# Print "lineno: entry" for every invalid line of a file.
invalid_ip_lines() {
    local n=0 line e
    while IFS= read -r line || [[ -n "$line" ]]; do
        n=$((n + 1)); e="$(line_entry "$line")"
        [[ -z "$e" ]] || valid_target "$e" || printf '  line %d: %s\n' "$n" "$e"
    done < "$1"
}

cmd_edit_ips() {
    local tmp editor bad reply
    require_admin --edit-ips
    [[ -f "$IPS_FILE" ]] || : > "$IPS_FILE"
    tmp="$(mktemp "${TMPDIR:-/tmp}/abuse-checker-ips.XXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -f '$tmp'" EXIT
    cat "$IPS_FILE" > "$tmp"
    editor="$(pick_editor)"
    # Invalid entries that were already there are reported but do not block.
    local before
    before="$(invalid_ip_lines "$IPS_FILE" | sed 's/^  line [0-9]*: //')"
    while true; do
        # shellcheck disable=SC2086  # allow EDITOR="code --wait"
        $editor "$tmp" || die "editor exited with an error; ips.txt unchanged"
        bad="$(invalid_ip_lines "$tmp" | while IFS= read -r l; do
                   grep -qxF -- "${l#*: }" <<< "$before" || printf '%s\n' "$l"; done)"
        [[ -n "$before" ]] && printf 'note: existing invalid entries (skipped at run time): %s\n' "$(paste -sd' ' - <<< "$before")" >&2
        [[ -z "$bad" ]] && break
        echo "warning: invalid IP/CIDR entries:" >&2
        echo "$bad" >&2
        if [[ -t 0 ]]; then
            read -r -p "[E]dit again, [s]ave anyway (invalid lines are skipped at run time), or [a]bort? " reply || reply=a
            case "$reply" in
                [Ss]*) break ;;
                [Aa]*) echo "aborted; ips.txt unchanged"; return 1 ;;
            esac
        else
            echo "not saving (no terminal to confirm); ips.txt unchanged" >&2
            return 1
        fi
    done
    if cmp -s "$tmp" "$IPS_FILE"; then echo "no changes"; return 0; fi
    replace_ips_file "$IPS_FILE" "$tmp"
    echo "saved $IPS_FILE ($(read_targets "$IPS_FILE" 2>/dev/null | wc -l) valid entr$( [[ "$(read_targets "$IPS_FILE" 2>/dev/null | wc -l)" == 1 ]] && echo y || echo ies))"
}

# ---------------------------------------------------------------------------
# Scheduling (--schedule)
# ---------------------------------------------------------------------------
TIMER_DROPIN_DIR="${ABUSE_CHECKER_TIMER_DROPIN_DIR:-/etc/systemd/system/abuse-checker.timer.d}"
SYSTEMCTL_BIN="${ABUSE_CHECKER_SYSTEMCTL:-systemctl}"
SYSTEMD_ANALYZE_BIN="${ABUSE_CHECKER_SYSTEMD_ANALYZE:-systemd-analyze}"
JOURNALCTL_BIN="${ABUSE_CHECKER_JOURNALCTL:-journalctl}"
DEFAULT_SCHEDULE="*-*-* 06:00:00"

systemd_running() { [[ -n "${ABUSE_CHECKER_SYSTEMCTL:-}" || -d /run/systemd/system ]]; }

# schedule_to_calendars SPEC -> one OnCalendar expression per line.
schedule_to_calendars() {
    local spec n t h m
    spec="$(trim "${1,,}")"
    spec="${spec#every }"
    case "$spec" in
        hourly|1h) echo "hourly" ;;
        daily|1d|24h) echo "$DEFAULT_SCHEDULE" ;;
        2x|2x/day|twice) printf '%s\n' "*-*-* 06:00:00" "*-*-* 18:00:00" ;;
        4x|4x/day) echo "*-*-* 00/6:00:00" ;;
        [0-9]h|[0-9][0-9]h)
            n="${spec%h}"; n=$((10#$n))
            case "$n" in 2|3|4|6|8|12) echo "*-*-* 00/$n:00:00" ;;
                *) echo "error: '${n}h' must divide 24 (1,2,3,4,6,8,12,24)" >&2; return 1 ;; esac ;;
        *)
            if [[ "$spec" =~ ^[0-9]{1,2}:[0-9]{2}([[:space:]]*,[[:space:]]*[0-9]{1,2}:[0-9]{2})*$ ]]; then
                IFS=',' read -r -a _times <<< "$spec"
                for t in "${_times[@]}"; do
                    t="$(trim "$t")"; h="${t%%:*}"; m="${t#*:}"
                    (( 10#$h <= 23 && 10#$m <= 59 )) || { echo "error: invalid time '$t'" >&2; return 1; }
                    printf '*-*-* %02d:%02d:00\n' "$((10#$h))" "$((10#$m))"
                done | awk '!seen[$0]++'
            else
                printf '%s\n' "$1"    # raw OnCalendar expression (validated below)
            fi ;;
    esac
}

# Validate with systemd-analyze when available; print next elapse times.
validate_calendar() {
    local c="$1"
    command -v "$SYSTEMD_ANALYZE_BIN" >/dev/null 2>&1 || return 0
    "$SYSTEMD_ANALYZE_BIN" calendar "$c" >/dev/null 2>&1
}

print_next_runs() {
    local c
    if command -v "$SYSTEMD_ANALYZE_BIN" >/dev/null 2>&1; then
        while IFS= read -r c; do
            [[ -n "$c" ]] || continue
            echo "  $c"
            "$SYSTEMD_ANALYZE_BIN" calendar --iterations=3 "$c" 2>/dev/null \
                | sed -n 's/^ *\(Next elapse\|Iteration #[0-9]*\|(in UTC)\): */    next: /p' | grep -v '(in UTC)' | head -n3 || true
        done
    fi
    if systemd_running; then
        echo "Timer next trigger: $("$SYSTEMCTL_BIN" show abuse-checker.timer -p NextElapseUSecRealtime --value 2>/dev/null || echo unknown)"
    fi
}

current_calendars() {
    local f="$TIMER_DROPIN_DIR/override.conf"
    if [[ -f "$f" ]]; then
        sed -n 's/^OnCalendar=\(..*\)$/\1/p' "$f"
    else
        sed -n 's/^OnCalendar=\(..*\)$/\1/p' "${ABUSE_CHECKER_TIMER_UNIT:-/etc/systemd/system/abuse-checker.timer}" 2>/dev/null \
            || echo "$DEFAULT_SCHEDULE"
    fi
}

cmd_schedule() {
    local spec="${1:-show}" cal f tmp
    local -a cals=()
    case "$spec" in
        show|"")
            echo "Schedule ($( [[ -f "$TIMER_DROPIN_DIR/override.conf" ]] && echo "custom: $TIMER_DROPIN_DIR/override.conf" || echo default)):"
            current_calendars | print_next_runs
            return 0 ;;
        reset|default)
            require_schedule_admin
            rm -f "$TIMER_DROPIN_DIR/override.conf"
            rmdir "$TIMER_DROPIN_DIR" 2>/dev/null || true
            reload_timer
            echo "schedule reset to the default (daily 06:00)"
            return 0 ;;
    esac
    require_schedule_admin
    mapfile -t cals < <(schedule_to_calendars "$spec") || true
    (( ${#cals[@]} > 0 )) || die "could not parse schedule '$spec'"
    for cal in "${cals[@]}"; do
        validate_calendar "$cal" || die "invalid OnCalendar expression: '$cal' (checked with systemd-analyze calendar)"
    done
    mkdir -p "$TIMER_DROPIN_DIR"
    f="$TIMER_DROPIN_DIR/override.conf"
    tmp="$(mktemp "$TIMER_DROPIN_DIR/.override.XXXXXX")"
    {
        echo "# Generated by 'abuse-checker --schedule $spec'"
        echo "[Timer]"
        echo "OnCalendar="
        for cal in "${cals[@]}"; do echo "OnCalendar=$cal"; done
    } > "$tmp"
    chmod 0644 "$tmp"; mv -f "$tmp" "$f"
    echo "wrote $f"
    reload_timer
    echo "New schedule:"
    printf '%s\n' "${cals[@]}" | print_next_runs
}

require_schedule_admin() {
    if [[ $EUID -ne 0 && -z "${ABUSE_CHECKER_TIMER_DROPIN_DIR:-}" ]]; then
        die "run as root: sudo abuse-checker --schedule ..."
    fi
}

reload_timer() {
    systemd_running || { echo "(systemd not running: drop-in written, timer not restarted)"; return 0; }
    if ! { "$SYSTEMCTL_BIN" daemon-reload && "$SYSTEMCTL_BIN" restart abuse-checker.timer; }; then
        warn "could not restart abuse-checker.timer"
    fi
}

# ---------------------------------------------------------------------------
# Watchdog (--watchdog-recover)
# ---------------------------------------------------------------------------
# Run by abuse-checker-watchdog.service (as root) via OnFailure= and on its
# own timer. Repairs what it can and alerts every connector when something
# was wrong. A healthy system produces no alert.
cmd_watchdog_recover() {
    local -a problems=() actions=()
    local lock="$STATE_DIR/.lock" last age max_h="${WATCHDOG_MAX_AGE_HOURS:-48}" logs body
    # 1. Failed service (OnFailure= path, or found by the periodic check).
    if systemd_running && "$SYSTEMCTL_BIN" is-failed --quiet abuse-checker.service 2>/dev/null; then
        problems+=("abuse-checker.service is in the failed state (all restart attempts used)")
        "$SYSTEMCTL_BIN" reset-failed abuse-checker.service 2>/dev/null && actions+=("reset the failed state of abuse-checker.service")
    fi
    # 2. Stale lock: file present but no process holds the flock.
    if [[ -e "$lock" ]]; then
        if command -v flock >/dev/null 2>&1 && flock -n "$lock" true 2>/dev/null; then
            if [[ -n "$(find "$lock" -mmin +"${WATCHDOG_LOCK_MAX_MIN:-20}" 2>/dev/null)" ]]; then
                rm -f "$lock"
                problems+=("stale lock $lock (no process held it)")
                actions+=("removed stale lock $lock")
            fi
        elif command -v flock >/dev/null 2>&1; then
            info "watchdog: a run is in progress (lock held); leaving it alone"
        fi
    fi
    # 3. Timer must be enabled and active.
    if systemd_running; then
        if ! "$SYSTEMCTL_BIN" is-enabled --quiet abuse-checker.timer 2>/dev/null; then
            problems+=("abuse-checker.timer was not enabled")
            "$SYSTEMCTL_BIN" enable abuse-checker.timer 2>/dev/null && actions+=("enabled abuse-checker.timer")
        fi
        if ! "$SYSTEMCTL_BIN" is-active --quiet abuse-checker.timer 2>/dev/null; then
            problems+=("abuse-checker.timer was not active")
            "$SYSTEMCTL_BIN" restart abuse-checker.timer 2>/dev/null && actions+=("restarted abuse-checker.timer")
        fi
    fi
    # 4. No successful run for too long.
    last="$(jq -r '.lastRun // empty' "$STATE_FILE" 2>/dev/null || true)"
    if [[ -n "$last" ]]; then
        age=$(( ( $(date +%s) - $(date -d "$last" +%s 2>/dev/null || date +%s) ) / 3600 ))
        if (( age > max_h )); then problems+=("no successful run for ${age}h (last: $last, limit ${max_h}h)"); fi
    fi

    if (( ${#problems[@]} == 0 )); then
        if systemd_running; then info "watchdog: healthy (timer active, no failed run, no stale lock)"
        else info "watchdog: healthy (no stale lock; systemd not running, unit checks skipped)"; fi
        return 0
    fi
    logs="$("$JOURNALCTL_BIN" -u abuse-checker.service -n 15 --no-pager -o short-iso 2>/dev/null | redact_stream || true)"
    body="$(
        echo "abuse-checker on $HOST_LABEL needed recovery at $(date '+%Y-%m-%d %H:%M %Z')."
        echo
        echo "Problems:"; printf ' - %s\n' "${problems[@]}"
        echo
        echo "Recovery actions:"
        if (( ${#actions[@]} )); then printf ' - %s\n' "${actions[@]}"; else echo " - none possible automatically"; fi
        echo
        echo "Last 15 log lines (redacted):"
        echo "${logs:-(journal not available)}"
    )"
    warn "watchdog: ${#problems[@]} problem(s): $(IFS='; '; echo "${problems[*]}")"
    ALERT_KIND="watchdog"
    ALERT_BODY="$body"
    export ALERT_KIND ALERT_BODY
    echo '[]' > "$TMPD/watchdog.json"
    notify_all "$TMPD/watchdog.json" "" "[WATCHDOG ALERT] abuse-checker on $HOST_LABEL crashed and was recovered"
    return 0
}

# ---------------------------------------------------------------------------
# System dependencies, OS upgrade and --doctor
# ---------------------------------------------------------------------------
# Tools the program needs. ca-certificates is checked as a CA bundle file.
REQUIRED_TOOLS=(bash curl jq awk sed openssl flock mktemp date base64 find tar ca-certificates)

pkg_manager() {
    local pm
    if [[ -n "${ABUSE_CHECKER_PKG_MGR:-}" ]]; then printf '%s' "$ABUSE_CHECKER_PKG_MGR"; return 0; fi
    for pm in apt-get dnf yum apk pacman zypper; do
        command -v "$pm" >/dev/null 2>&1 && { printf '%s' "$pm"; return 0; }
    done
    return 1
}

# Package that provides a tool, per package manager.
tool_pkg() {
    local pm="$1" t="$2"
    case "$t" in
        awk) echo gawk ;;
        flock) if [[ "$pm" == "apk" ]]; then echo flock; else echo util-linux; fi ;;
        mktemp|date|base64) echo coreutils ;;
        find) echo findutils ;;
        *) echo "$t" ;;
    esac
}

have_ca_bundle() {
    local f
    for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem /etc/ssl/ca-bundle.pem; do
        [[ -s "$f" ]] && return 0
    done
    return 1
}

# have_tool NAME (ABUSE_CHECKER_FAKE_MISSING_FILE lets tests simulate gaps)
have_tool() {
    if [[ -n "${ABUSE_CHECKER_FAKE_MISSING_FILE:-}" && -f "$ABUSE_CHECKER_FAKE_MISSING_FILE" ]] \
       && grep -qx -- "$1" "$ABUSE_CHECKER_FAKE_MISSING_FILE"; then
        return 1
    fi
    if [[ "$1" == "ca-certificates" ]]; then have_ca_bundle; else command -v "$1" >/dev/null 2>&1; fi
}

missing_tools() { local t; for t in "${REQUIRED_TOOLS[@]}"; do have_tool "$t" || echo "$t"; done; return 0; }

can_manage_packages() { [[ $EUID -eq 0 || -n "${ABUSE_CHECKER_PKG_CMD:-}" ]]; }

# pkg_run refresh|install PKG...|upgrade  (non-interactive, quiet)
pkg_run() {
    local action="$1"; shift
    local pm bin
    pm="$(pkg_manager)" || { warn "no supported package manager (apt-get, dnf, yum, apk, pacman, zypper)"; return 1; }
    bin="${ABUSE_CHECKER_PKG_CMD:-$pm}"
    case "$pm:$action" in
        apt-get:refresh) "$bin" update -qq ;;
        apt-get:install) env DEBIAN_FRONTEND=noninteractive "$bin" install -y -qq --no-install-recommends "$@" ;;
        apt-get:upgrade) env DEBIAN_FRONTEND=noninteractive "$bin" -y -qq \
                             -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade ;;
        dnf:refresh|yum:refresh) "$bin" -q -y makecache ;;
        dnf:install|yum:install) "$bin" -q -y install "$@" ;;
        dnf:upgrade|yum:upgrade) "$bin" -q -y upgrade ;;
        apk:refresh) "$bin" -q update ;;
        apk:install) "$bin" -q add --no-cache "$@" ;;
        apk:upgrade) "$bin" -q upgrade --no-cache ;;
        pacman:refresh) "$bin" -Sy --noconfirm ;;
        pacman:install) "$bin" -S --needed --noconfirm "$@" ;;
        pacman:upgrade) "$bin" -Syu --noconfirm ;;
        zypper:refresh) "$bin" --non-interactive --quiet refresh ;;
        zypper:install) "$bin" --non-interactive --quiet install --no-recommends "$@" ;;
        zypper:upgrade) "$bin" --non-interactive --quiet update ;;
        *) warn "unsupported package manager action: $pm $action"; return 1 ;;
    esac
}

os_upgrade() {
    can_manage_packages || { warn "OS upgrade needs root"; return 1; }
    info "upgrading system packages with $(pkg_manager || echo '?') (non-interactive)"
    pkg_run refresh >&2 && pkg_run upgrade >&2
}

# Install whatever is missing. Prints the tools that were installed.
install_missing_deps() {
    local -a miss=() pkgs=()
    local pm t
    mapfile -t miss < <(missing_tools)
    (( ${#miss[@]} == 0 )) && return 0
    can_manage_packages || { warn "missing: ${miss[*]} (run as root to install them)"; return 1; }
    pm="$(pkg_manager)" || { warn "missing: ${miss[*]}; no supported package manager found"; return 1; }
    for t in "${miss[@]}"; do pkgs+=("$(tool_pkg "$pm" "$t")"); done
    mapfile -t pkgs < <(printf '%s\n' "${pkgs[@]}" | awk '!seen[$0]++')
    info "installing missing dependencies with $pm: ${pkgs[*]}"
    # Package-manager output goes to stderr: stdout carries only the result list.
    pkg_run refresh >&2 || warn "package metadata refresh failed; trying to install anyway"
    pkg_run install "${pkgs[@]}" >&2 || { warn "package installation failed"; return 1; }
    local -a still=()
    mapfile -t still < <(missing_tools)
    (( ${#still[@]} == 0 )) || { warn "still missing after install: ${still[*]}"; return 1; }
    printf '%s\n' "${miss[@]}"
}

# --install-deps [--upgrade-os]: used by install.sh before anything else.
cmd_install_deps() {
    local upgrade="$1" got
    if $upgrade; then os_upgrade || warn "OS upgrade failed; continuing"; fi
    if got="$(install_missing_deps)"; then
        [[ -n "$got" ]] && echo "installed: $(paste -sd' ' - <<< "$got")"
        echo "all dependencies present"
        return 0
    fi
    echo "error: missing dependencies: $(missing_tools | paste -sd' ' -)" >&2
    return 1
}

DOC_OK=0 DOC_WARN=0 DOC_FIXED=0
dok()  { DOC_OK=$((DOC_OK + 1));       printf '[OK]    %s\n' "$*"; }
dwarn(){ DOC_WARN=$((DOC_WARN + 1));   printf '[WARN]  %s\n' "$*"; }
dfix() { DOC_FIXED=$((DOC_FIXED + 1)); printf '[FIXED] %s\n' "$*"; }

# doctor_perm PATH MODE OWNER:GROUP [label]  (fixes as root)
doctor_perm() {
    local path="$1" mode="$2" owner="$3" label="${4:-$1}" cur_mode cur_owner
    [[ -e "$path" ]] || return 0
    if [[ "$owner" == *"$SERVICE_USER"* ]] && ! id "$SERVICE_USER" >/dev/null 2>&1; then owner=""; fi
    cur_mode="$(stat -c %a "$path")"; cur_owner="$(stat -c %U:%G "$path")"
    if [[ "$cur_mode" == "$mode" && ( -z "$owner" || "$cur_owner" == "$owner" ) ]]; then
        dok "$label ($cur_mode ${cur_owner})"
    elif [[ $EUID -eq 0 ]]; then
        chmod "$mode" "$path"; [[ -z "$owner" ]] || chown "$owner" "$path"
        dfix "$label: $cur_mode $cur_owner -> $mode ${owner:-$cur_owner}"
    else
        dwarn "$label is $cur_mode $cur_owner, expected $mode ${owner:-}"
    fi
}

cmd_doctor() {
    local upgrade="$1" pm t got ver free_mb code min_mb="${DOCTOR_MIN_FREE_MB:-100}"
    echo "abuse-checker v$AC_VERSION system check"
    echo
    # OS
    if [[ -r "${ABUSE_CHECKER_OS_RELEASE:-/etc/os-release}" ]]; then
        # shellcheck source=/dev/null
        dok "OS: $( . "${ABUSE_CHECKER_OS_RELEASE:-/etc/os-release}"; echo "${PRETTY_NAME:-$ID}" ) (kernel $(uname -r))"
    else
        dwarn "OS: /etc/os-release not found"
    fi
    if pm="$(pkg_manager)"; then dok "package manager: $pm"; else dwarn "no supported package manager found"; fi
    if $upgrade; then
        if os_upgrade >/dev/null 2>&1; then dfix "system packages upgraded"; else dwarn "OS upgrade failed or not permitted"; fi
    fi
    # Dependencies
    local -a miss=()
    mapfile -t miss < <(missing_tools)
    if (( ${#miss[@]} == 0 )); then
        dok "dependencies: ${REQUIRED_TOOLS[*]}"
    elif got="$(install_missing_deps 2>/dev/null)"; then
        for t in $got; do dfix "installed missing dependency: $t"; done
    else
        for t in $(missing_tools); do dwarn "missing dependency: $t$(can_manage_packages || echo ' (run as root to install)')"; done
    fi
    # Versions
    if (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )); then
        dok "bash $BASH_VERSION (>= 4.4)"
    else
        dwarn "bash $BASH_VERSION is older than 4.4"
    fi
    have_tool curl && dok "curl $(curl --version 2>/dev/null | awk 'NR==1{print $2}')"
    have_tool jq && dok "jq $(jq --version 2>/dev/null | sed 's/^jq-//')"
    have_tool openssl && dok "openssl $(openssl version 2>/dev/null | awk '{print $2}')"
    # Service user and files
    if id "$SERVICE_USER" >/dev/null 2>&1; then dok "service user $SERVICE_USER exists"
    else dwarn "service user $SERVICE_USER missing (run install.sh)"; fi
    if [[ -d "$CONF_DIR" ]]; then
        doctor_perm "$CONF_DIR" 755 root:root
        doctor_perm "$IPS_FILE" 644 "root:$SERVICE_USER"
        doctor_perm "$ENC_FILE" 640 "root:$SERVICE_USER"
        doctor_perm "$MASTER_KEY" 400 root:root
        doctor_perm "$CRED_FILE" 600 root:root
        doctor_perm "$SECRETS_FILE" 600 root:root
        [[ -f "$SECRETS_FILE" ]] && dwarn "secrets stored in plain text; run: sudo abuse-checker --encrypt-secrets"
        [[ -e "$IPS_FILE" ]] || dwarn "$IPS_FILE missing"
    else
        dwarn "$CONF_DIR missing (run install.sh)"
    fi
    if [[ -d "$STATE_DIR" ]]; then
        doctor_perm "$STATE_DIR" 750 "$SERVICE_USER:$SERVICE_USER"
        doctor_perm "$STATE_DIR/reports" 750 "$SERVICE_USER:$SERVICE_USER"
        doctor_perm "$STATE_FILE" 640 "$SERVICE_USER:$SERVICE_USER"
        free_mb="$(df -Pk "$STATE_DIR" 2>/dev/null | awk 'NR==2{print int($4/1024)}')"
        if [[ -n "$free_mb" ]]; then
            if (( free_mb >= min_mb )); then dok "free disk space in $STATE_DIR: ${free_mb} MB"
            else dwarn "low disk space in $STATE_DIR: ${free_mb} MB (< ${min_mb} MB)"; fi
        fi
    else
        dwarn "$STATE_DIR missing (run install.sh)"
    fi
    # systemd
    if systemd_running; then
        local u
        for u in abuse-checker.timer abuse-checker-watchdog.timer; do
            if "$SYSTEMCTL_BIN" is-enabled --quiet "$u" 2>/dev/null && "$SYSTEMCTL_BIN" is-active --quiet "$u" 2>/dev/null; then
                dok "$u enabled and active"
            elif [[ $EUID -eq 0 ]] && "$SYSTEMCTL_BIN" enable --now "$u" >/dev/null 2>&1; then
                dfix "$u enabled and started"
            else
                dwarn "$u is not enabled/active"
            fi
        done
        if "$SYSTEMCTL_BIN" is-failed --quiet abuse-checker.service 2>/dev/null; then
            if [[ $EUID -eq 0 ]] && "$SYSTEMCTL_BIN" reset-failed abuse-checker.service 2>/dev/null; then
                dfix "abuse-checker.service was failed; state reset (see journalctl -u abuse-checker)"
            else
                dwarn "abuse-checker.service is in the failed state"
            fi
        else
            dok "abuse-checker.service not failed"
        fi
    else
        dwarn "systemd not running: timer/service checks skipped"
    fi
    # Connectivity (no API key needed: any HTTP answer proves reachability)
    if have_tool curl; then
        code="$(secure_curl "$(cfg_line url "${ABUSE_CHECKER_DOCTOR_URL:-https://api.abuseipdb.com/api/v2/check}")" \
                --max-time 15 -o /dev/null -w '%{http_code}' 2>/dev/null)" || code="000"
        if [[ "$code" != "000" ]]; then dok "HTTPS to api.abuseipdb.com reachable (HTTP $code)"
        else dwarn "cannot reach https://api.abuseipdb.com (DNS, firewall or proxy?)"; fi
    fi
    echo
    echo "Summary: $DOC_OK OK, $DOC_FIXED fixed, $DOC_WARN warning(s)"
    (( DOC_WARN == 0 ))
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
    $DRY_RUN || update_notice_check
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
    echo "Updates     : AUTO_UPDATE=${AUTO_UPDATE:-notify} from $(repo_slug)@$(repo_branch)$( [[ -r "$STATE_DIR/update-check.json" ]] && jq -r '" (latest seen: v\(.latest))"' "$STATE_DIR/update-check.json" 2>/dev/null)"
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
IP pool (root):
  --list-ips, --ips     Numbered list of ips.txt with status from state.json
  --add-ip IP|CIDR [...] [--comment TEXT]
                        Validate and append entries (duplicates are skipped)
  --del-ip, --rm-ip IP|CIDR [...]
                        Remove entries from ips.txt and their state
  --edit-ips            Edit ips.txt in \$EDITOR with validation on save

Scheduling & recovery (root):
  --schedule SPEC       "06:00,18:00" | hourly | 6h | "every 12h" | daily |
                        raw OnCalendar | show | reset
  --watchdog-recover    Repair failed service/stale lock/inactive timer and alert
  --doctor, --check-system [--upgrade-os]
                        System checklist: OS, dependencies (auto-installed),
                        versions, permissions, systemd, disk, connectivity

  --check-update        Compare the installed version with GitHub ($DEFAULT_REPO_SLUG)
  --update, --self-update [--force]
                        Download, verify (bash -n) and install the latest version
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
            --check-update) MODE="check-update" ;;
            --update|--self-update) MODE="update" ;;
            --force) extra="force" ;;
            --auto-update) MODE="auto-update" ;;
            --list-ips|--ips) MODE="list-ips" ;;
            --add-ip) MODE="add-ip"
                while (( $# )) && [[ "$1" != --* ]]; do IP_ARGS+=("$1"); shift; done ;;
            --del-ip|--rm-ip) MODE="del-ip"
                while (( $# )) && [[ "$1" != --* ]]; do IP_ARGS+=("$1"); shift; done ;;
            --comment) IP_COMMENT="${1?--comment needs text}"; shift ;;
            --edit-ips) MODE="edit-ips" ;;
            --schedule) MODE="schedule"; extra="${1:-show}"; (( $# )) && shift ;;
            --watchdog-recover) MODE="watchdog" ;;
            --doctor|--check-system) MODE="doctor" ;;
            --install-deps) MODE="install-deps" ;;
            --upgrade-os) UPGRADE_OS=true ;;
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
        list-ips) cmd_list_ips; return ;;
        add-ip) cmd_add_ip "$IP_COMMENT" "${IP_ARGS[@]}"; return ;;
        del-ip) cmd_del_ip "${IP_ARGS[@]}"; return ;;
        edit-ips) cmd_edit_ips; return ;;
        schedule) cmd_schedule "$extra"; return ;;
        doctor) cmd_doctor "$UPGRADE_OS"; return ;;
        install-deps) cmd_install_deps "$UPGRADE_OS"; return ;;
    esac
    load_config
    install_redaction
    require_tools
    case "$MODE" in
        check-update) cmd_check_update; return ;;
        update) cmd_update "$extra"; return ;;
        auto-update) cmd_auto_update; return ;;
    esac
    setup_tmp
    case "$MODE" in
        watchdog) cmd_watchdog_recover ;;
        run) cmd_run ;;
        test-notify) cmd_test_notify ;;
        status) cmd_status ;;
        reset) cmd_reset_state ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
