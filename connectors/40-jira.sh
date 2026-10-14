# shellcheck shell=bash
# abuse-checker connector: Jira
# Loaded by abuse-checker from /usr/local/lib/abuse-checker/connectors.d/ in a
# subshell. Interface: connector_enabled (return 0 when configured) and
# connector_send <classified.json> <report.html> <title>.
#
# Settings (from the encrypted secrets store):
#   JIRA_URL            https://your-org.atlassian.net (or Server/DC base URL)
#   JIRA_API_TOKEN      Cloud API token, or a Server/DC personal access token
#   JIRA_EMAIL          Cloud account e-mail (Basic auth). Leave empty to use
#                       JIRA_API_TOKEN as a Bearer PAT (Server/Data Center).
#   JIRA_PROJECT_KEY    e.g. SEC
#   JIRA_ISSUE_TYPE     default "Task"
#   JIRA_UPDATE_MODE    "comment" (default): comment on the newest open
#                       abuse-checker issue for this host, create one if none;
#                       "create": always open a new issue
#   JIRA_LABELS         extra labels, comma-separated (optional)
#   JIRA_PRIORITY       priority name, e.g. "High" (optional)
#   JIRA_ATTACH_REPORT  "true" (default) attaches the HTML report
#
# The token and the derived Authorization header travel only through
# `curl --config -` (stdin); they never appear in argv or logs.

# shellcheck disable=SC2034  # read by abuse-checker
CONNECTOR_NAME="Jira"

connector_enabled() {
    [[ -n "${JIRA_URL:-}" && -n "${JIRA_API_TOKEN:-}" && -n "${JIRA_PROJECT_KEY:-}" ]]
}

# Auth header line for the curl config (Basic for Cloud, Bearer for PAT).
_jira_auth() {
    if [[ -n "${JIRA_EMAIL:-}" ]]; then
        cfg_line header "Authorization: Basic $(printf '%s:%s' "$JIRA_EMAIL" "$JIRA_API_TOKEN" | base64 -w0)"
    else
        cfg_line header "Authorization: Bearer $JIRA_API_TOKEN"
    fi
}

# _jira_call METHOD PATH [json-body-file]
# Sets JIRA_CODE (HTTP status) and leaves the response body in $JIRA_OUT.
# Not meant for $(...): the status must survive in the caller's shell.
JIRA_CODE="000"
JIRA_OUT=""
_jira_call() {
    local method="$1" path="$2" body="${3:-}" out="$TMPD/jira.out" cfg
    JIRA_OUT="$out"; : > "$out"
    cfg="$(cfg_line url "${JIRA_URL%/}$path")
$(_jira_auth)
$(cfg_line header "Accept: application/json")
$(cfg_line request "$method")"
    if [[ -n "$body" ]]; then
        cfg+=$'\n'"$(cfg_line header "Content-Type: application/json")"
        JIRA_CODE="$(secure_curl "$cfg" --max-time 30 -o "$out" -w '%{http_code}' --data-binary "@$body")" || JIRA_CODE="000"
    else
        JIRA_CODE="$(secure_curl "$cfg" --max-time 30 -o "$out" -w '%{http_code}')" || JIRA_CODE="000"
    fi
    return 0
}

# Newest open abuse-checker issue for this host; result in JIRA_OPEN_KEY.
JIRA_OPEN_KEY=""
_jira_find_open() {
    local jql
    JIRA_OPEN_KEY=""
    jql="project = \"$JIRA_PROJECT_KEY\" AND labels = \"abuse-checker\" AND labels = \"$(_jira_host_label)\" AND statusCategory != Done ORDER BY created DESC"
    # Jira Cloud: /rest/api/3/search/jql ; Server/DC: /rest/api/2/search
    _jira_call GET "/rest/api/3/search/jql?jql=$(urlencode "$jql")&maxResults=1&fields=key"
    if [[ "$JIRA_CODE" == "404" || "$JIRA_CODE" == "410" ]]; then
        _jira_call GET "/rest/api/2/search?jql=$(urlencode "$jql")&maxResults=1&fields=key"
    fi
    [[ "$JIRA_CODE" == "200" ]] || { warn "Jira search failed (HTTP $JIRA_CODE); creating a new issue"; return 0; }
    JIRA_OPEN_KEY="$(jq -r '.issues[0].key // empty' "$JIRA_OUT" 2>/dev/null)"
}

_jira_host_label() { printf 'abuse-checker-%s' "$(printf '%s' "$HOST_LABEL" | tr -c 'A-Za-z0-9_.-' '-')"; }

# Jira wiki-markup text (REST v2 accepts it for description and comments).
_jira_text() {
    jq -r --arg title "$3" --arg report "$(basename "$2")" --arg upd "${UPDATE_NOTICE:-}" --argjson force "$FORCE_FULL" '
        def esc: tostring | gsub("\\|"; "/") | gsub("[\\[\\]{}]"; "");
        [.[] | select(.status=="NEW" or .status=="ESCALATED" or ($force and .status=="UNCHANGED"))] as $a
        | "h3. \($title | esc)",
          "Checked: *\(length)* | New: *\(map(select(.status=="NEW"))|length)* | Escalated: *\(map(select(.status=="ESCALATED"))|length)* | Unchanged dirty: \(map(select(.status=="UNCHANGED"))|length)",
          "",
          "||Status||IP / Subnet||Score||Reports||ISP||Country||Last reported||AbuseIPDB||",
          ($a[:50][] | "|\(.status)|{{\(.target)}}|\(.score)%|\(.total)" + (if .delta > 0 then " (+\(.delta))" else "" end)
             + "|\((.isp // "-") | esc) |\(.country // "-") |\((.last // "-") | esc)|[check|https://www.abuseipdb.com/check/\(.target | @uri)]|"),
          (if ($a|length) > 50 then "_…and \(($a|length) - 50) more, see the attached report._" else empty end),
          "",
          "_Full interactive report: \($report)_",
          (if $upd != "" then "_\($upd)_" else empty end)' "$1"
}

connector_send() {
    local data="$1" report="$2" title="$3" text key payload="$TMPD/jira.json" labels
    text="$(_jira_text "$data" "$report" "$title")"
    key=""
    if [[ "${JIRA_UPDATE_MODE:-comment}" != "create" ]]; then
        _jira_find_open; key="$JIRA_OPEN_KEY"
    fi

    if [[ -n "$key" ]]; then
        jq -n --arg body "$text" '{body:$body}' > "$payload"
        _jira_call POST "/rest/api/2/issue/$key/comment" "$payload"
        [[ "$JIRA_CODE" == "201" || "$JIRA_CODE" == "200" ]] || { warn "Jira comment on $key failed (HTTP $JIRA_CODE)"; return 1; }
        info "Jira: updated $key with a new comment"
    else
        labels="$( { printf 'abuse-checker\n%s\n' "$(_jira_host_label)"; split_csv "${JIRA_LABELS:-}"; } | jq -R . | jq -sc 'unique')"
        jq -n --arg p "$JIRA_PROJECT_KEY" --arg t "${JIRA_ISSUE_TYPE:-Task}" --arg s "${title:0:250}" \
              --arg d "$text" --argjson labels "$labels" --arg prio "${JIRA_PRIORITY:-}" \
            '{fields:({project:{key:$p}, issuetype:{name:$t}, summary:$s, description:$d, labels:$labels}
                      + (if $prio != "" then {priority:{name:$prio}} else {} end))}' > "$payload"
        _jira_call POST "/rest/api/2/issue" "$payload"
        key="$(jq -r '.key // empty' "$JIRA_OUT" 2>/dev/null)"
        [[ "$JIRA_CODE" == "201" && -n "$key" ]] || {
            warn "Jira issue creation failed (HTTP $JIRA_CODE): $(jq -r '[.errorMessages[]?, (.errors // {} | to_entries[] | "\(.key): \(.value)")] | join("; ")' "$JIRA_OUT" 2>/dev/null)"
            return 1
        }
        info "Jira: created $key"
    fi

    if [[ "${JIRA_ATTACH_REPORT:-true}" == "true" && -f "$report" ]]; then
        local cfg code
        cfg="$(cfg_line url "${JIRA_URL%/}/rest/api/2/issue/$key/attachments")
$(_jira_auth)
$(cfg_line header "X-Atlassian-Token: no-check")
$(cfg_line form "file=@$report;type=text/html")"
        code="$(secure_curl "$cfg" --max-time 60 -o /dev/null -w '%{http_code}')" || code="000"
        [[ "$code" == "200" ]] || warn "Jira: attaching report to $key failed (HTTP $code)"
    fi
    return 0
}
