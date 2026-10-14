# abuse-checker

**English** · [Українська](README.uk.md)

A small, dependency-light AbuseIPDB monitor for Linux servers. It is written in
plain Bash and uses only `curl`, `jq`, `awk`, `sed`, `date`, `mktemp` and
coreutils. Once a day a systemd timer checks a list of your IPs and subnets
against [AbuseIPDB](https://www.abuseipdb.com/). You only get an alert, with a
self-contained interactive HTML report, when something has changed: a newly
flagged IP or new reports against one that was already flagged.

Alerts can go to several Telegram chats, Slack webhooks and email recipients
at once.

---

## Contents

- [How it works](#how-it-works)
- [File locations (FHS)](#file-locations-fhs)
- [Installation](#installation)
- [Configuration](#configuration)
- [Managing IPs and recipients](#managing-ips-and-recipients)
- [CLI reference](#cli-reference)
- [Daily maintenance](#daily-maintenance)
- [Updating](#updating)
- [Uninstalling](#uninstalling)
- [Security model](#security-model)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

---

## How it works

1. Reads `/etc/abuse-checker/ips.txt`. Single IPs (IPv4 or IPv6) are queried
   with `GET /api/v2/check?maxAgeInDays=30&verbose`. CIDR blocks are queried
   with `GET /api/v2/check-block`. If you set `USE_CHECK_BLOCK=false`, small
   IPv4 blocks (up to `EXPAND_MAX_HOSTS` addresses) are instead expanded and
   checked one IP at a time.
2. Each result is compared with `/var/lib/abuse-checker/state.json`. An IP is
   **dirty** when `abuseConfidenceScore > THRESHOLD` or `totalReports > 0`.

   | Status      | Meaning                                                                          |
   |-------------|----------------------------------------------------------------------------------|
   | `CLEAN`     | Not dirty                                                                        |
   | `NEW`       | Dirty now, but clean or unseen at the previous check                             |
   | `ESCALATED` | Already dirty, and `totalReports` went up **or** `lastReportedAt` is newer       |
   | `UNCHANGED` | Still dirty, no new reports since the previous check                             |
   | `ERROR`     | The API call failed. The previous state for this IP is kept.                     |

   For a CIDR, the score is the highest score in the block, the reports are
   summed across the block, and `lastReportedAt` is the most recent report.
3. **Alert rule:** a report is generated and notifications are sent **only if
   at least one IP is `NEW` or `ESCALATED`**. The exception is
   `--force-full-report`, which alerts on every dirty IP. The number of
   `UNCHANGED` IPs is shown in the footer.
4. The state file is written atomically. Reports older than `RETENTION_DAYS`
   are deleted.

### API keys and failover

`ABUSEIPDB_API_KEYS="key1,key2,..."`. The checker uses the first key until one
of these happens:

- it returns HTTP `429`, `401` or `403`; or
- a response carries `X-RateLimit-Remaining: 0`.

It then moves to the next key. If every key is used up, the IPs that were not
checked keep their previous state and are checked on the next run. Logs refer
to keys only as `key #N`.

### HTML report

The report is saved as `/var/lib/abuse-checker/reports/report_YYYY-MM-DD.html`.
It is one file with inline CSS and about 1 KB of vanilla JS, and loads nothing
from outside (about 6–15 KB for typical pools). It contains:

- summary cards: Total checked, Clean, New, Escalated, Unchanged dirty, Errors;
- a table you can filter and sort by clicking column headers. Columns: status
  badge, IP/subnet, colour-coded score, total reports with a `+delta` badge,
  ISP/domain, country, last reported time, and a button to
  `https://www.abuseipdb.com/check/<IP>`;
- automatic dark mode.

---

## File locations (FHS)

| Path                                         | Mode   | Owner                       | Purpose                                     |
|----------------------------------------------|--------|-----------------------------|---------------------------------------------|
| `/usr/local/bin/abuse-checker`               | `0755` | `root:root`                 | Main executable (in `$PATH`)                |
| `/etc/abuse-checker/secrets.conf`            | `0600` | `root:root`                 | API keys, tokens, webhooks, SMTP, settings  |
| `/etc/abuse-checker/secrets.conf.example`    | `0644` | `root:root`                 | Reference copy of every setting             |
| `/etc/abuse-checker/ips.txt`                 | `0644` | `root:abusechecker`         | IPs and CIDRs to monitor                    |
| `/var/lib/abuse-checker/state.json`          | `0640` | `abusechecker:abusechecker` | Diff state database                         |
| `/var/lib/abuse-checker/state.dryrun.json`   | `0640` | `abusechecker:abusechecker` | Separate state used by `--dry-run`          |
| `/var/lib/abuse-checker/reports/`            | `0750` | `abusechecker:abusechecker` | Generated `.html` reports                   |
| `/etc/systemd/system/abuse-checker.service`  | `0644` | `root:root`                 | Sandboxed oneshot service                   |
| `/etc/systemd/system/abuse-checker.timer`    | `0644` | `root:root`                 | Daily trigger (06:00 + up to 15 min jitter) |
| `/usr/local/share/doc/abuse-checker/`        | `0755` | `root:root`                 | This README                                 |

Repository layout:

```
abuse-checker.sh            main script (installed as /usr/local/bin/abuse-checker)
install.sh / uninstall.sh   installer and remover
systemd/                    service and timer units
config/                     secrets.conf.example, ips.txt.example
tests/run_tests.sh          offline test suite (uses tests/mock_curl.sh)
```

---

## Installation

Requirements: a systemd-based Linux, Bash 4.4+, `curl` 7.55+ and `jq` 1.6+.

```bash
# Debian/Ubuntu
sudo apt install -y curl jq
# RHEL/Alma/Rocky/Fedora
sudo dnf install -y curl jq

git clone <this repo> abuse-checker && cd abuse-checker
bash tests/run_tests.sh          # optional: run the offline test suite first
sudo ./install.sh                # creates user, dirs, units; enables the timer
```

`install.sh` is idempotent. It **never overwrites** an existing
`secrets.conf`, `ips.txt` or `state.json`; it only corrects their ownership and
permissions. Use `--no-enable` to install without starting the timer.

Then:

```bash
sudo editor /etc/abuse-checker/secrets.conf   # at least ABUSEIPDB_API_KEYS
sudo editor /etc/abuse-checker/ips.txt
sudo abuse-checker --dry-run                   # mock data, checks the pipeline
sudo abuse-checker --test-notify               # sends a test alert to every channel
sudo systemctl start abuse-checker.service     # first real run
journalctl -u abuse-checker -n 50 --no-pager
```

> The first real run marks every dirty IP as `NEW`, so expect one larger
> alert. After that you only hear about changes.

---

## Configuration

Everything lives in `/etc/abuse-checker/secrets.conf`. systemd reads it via
`EnvironmentFile=`, and the script sources it when run as root. Write plain
`KEY="value"` lines only: no `$variables` and no command substitution, because
systemd does not expand them.

| Variable              | Default         | Description                                                      |
|-----------------------|-----------------|------------------------------------------------------------------|
| `ABUSEIPDB_API_KEYS`  | –               | Comma-separated API keys; failover in order                      |
| `THRESHOLD`           | `25`            | Score above which an IP counts as dirty                          |
| `MAX_AGE_DAYS`        | `30`            | `maxAgeInDays` sent to the API                                   |
| `USE_CHECK_BLOCK`     | `true`          | `false` = expand small IPv4 CIDRs and check each IP              |
| `EXPAND_MAX_HOSTS`    | `256`           | Largest CIDR to expand when `USE_CHECK_BLOCK=false`              |
| `REQUEST_DELAY`       | `0`             | Seconds to sleep between API calls                               |
| `RETENTION_DAYS`      | `30`            | Delete reports older than this                                   |
| `HOST_LABEL`          | hostname        | Name shown in alerts and reports                                 |
| `TELEGRAM_BOT_TOKEN`  | –               | Bot token from @BotFather                                        |
| `TELEGRAM_CHAT_IDS`   | –               | Comma-separated chat ids (DMs and groups; groups are negative)   |
| `SLACK_WEBHOOK_URLS`  | –               | Comma-separated incoming webhook URLs                            |
| `EMAIL_TO`            | –               | Comma-separated recipients                                       |
| `EMAIL_FROM`          | `abuse-checker@<host>` | Sender address                                            |
| `SMTP_URL`            | –               | `smtps://host:465` or `smtp://host:587` (STARTTLS enforced)      |
| `SMTP_USER`/`SMTP_PASS` | –             | SMTP credentials. Without `SMTP_URL`, local `sendmail -t` is used |

Free AbuseIPDB plans allow `check-block` only on networks up to `/24`. For
larger blocks, split them or use `USE_CHECK_BLOCK=false` with a smaller range.

---

## Managing IPs and recipients

### IPs and subnets

```bash
sudo editor /etc/abuse-checker/ips.txt
```

```
# one entry per line, '#' comments allowed
203.0.113.10
203.0.113.11          # mail relay
198.51.100.0/28       # office range
2001:db8::1
```

Invalid lines are skipped and logged with a warning. Duplicate lines are
ignored. When you remove an entry, its state is dropped on the next run. When
you add one, it is reported as `NEW` the first time it is dirty. You do not
need to restart anything; the next run picks up the change.

### Recipients

All of these settings take comma-separated lists. Edit `secrets.conf`, then
check delivery:

```bash
sudo editor /etc/abuse-checker/secrets.conf
sudo abuse-checker --test-notify
```

- **Telegram:** create a bot with @BotFather and add it to each group.
  To find chat ids, send the bot a message and open
  `https://api.telegram.org/bot<TOKEN>/getUpdates` in a browser (never paste the
  token into a shell history on a shared host). Each chat receives an HTML
  summary (`sendMessage`) and the report as a file (`sendDocument`).
- **Slack:** create one *Incoming Webhook* per channel or workspace and add
  every URL to `SLACK_WEBHOOK_URLS`. Messages use Block Kit and include a
  button per IP.
- **Email:** one message goes to all recipients, with the plain-text summary
  in the body and the HTML report attached.

---

## CLI reference

```
abuse-checker [--run | --dry-run | --test-notify | --force-full-report | --status | --reset-state]
```

| Flag                  | Effect |
|-----------------------|--------|
| `--run`               | Default. Run the check, update state, alert on `NEW`/`ESCALATED`. |
| `--dry-run`           | Use built-in mock API responses and a separate `state.dryrun.json`. Writes `report_<date>_dryrun.html`. Sends no notifications and makes no network calls. Uses the sample targets if `ips.txt` is not readable. |
| `--test-notify`       | Build a sample report (`report_<date>_test.html`) and send it to every configured channel. Does not touch the state. |
| `--force-full-report` | Normal run, but alerts on **every** dirty IP, including `UNCHANGED` ones. |
| `--status`            | Shows tracked IPs, dirty/clean counts, last run, report count, number of keys and the next timer trigger. |
| `--reset-state`       | Clears `state.json` (and the dry-run state). The next run treats every dirty IP as `NEW`. |
| `--help`, `--version` | Show usage or the version. |

When run by hand, use `sudo abuse-checker ...` so the script can read
`secrets.conf`. Or run it as the service user, with the secrets loaded by systemd:
`sudo systemctl start abuse-checker.service`.

---

## Daily maintenance

```bash
abuse-checker --status                         # summary + next trigger (as root)
systemctl list-timers abuse-checker.timer      # when the next run is
journalctl -u abuse-checker --since today      # logs from today's run
sudo systemctl start abuse-checker.service     # run now, as the service would
sudo ls -lt /var/lib/abuse-checker/reports/    # recent reports
sudo abuse-checker --force-full-report         # re-send a complete picture
```

To change the schedule, run `sudo systemctl edit abuse-checker.timer` and add:

```ini
[Timer]
OnCalendar=
OnCalendar=*-*-* 07:30:00
```

---

## Updating

```bash
cd abuse-checker && git pull
bash tests/run_tests.sh
sudo ./install.sh
```

The installer replaces the binary atomically and refreshes the units and
`secrets.conf.example`. Your config, IP list and state are left alone. Compare
`secrets.conf.example` with your `secrets.conf` to find new settings.

---

## Uninstalling

```bash
sudo ./uninstall.sh           # interactive; defaults to KEEPING config and state
sudo ./uninstall.sh --keep    # non-interactive, keep /etc and /var/lib data
sudo ./uninstall.sh --purge   # remove everything including the system user
```

The units and the binary are always removed. The `abusechecker` user is only
deleted when both data directories are deleted too.

---

## Security model

- **No secrets in the process list.** Every `curl` call gets its URL and
  headers through `curl --config -` on stdin. API keys, the Telegram token
  (which is part of the URL), Slack webhook URLs and SMTP credentials never
  appear in `argv`, so `ps aux` and `/proc/<pid>/cmdline` cannot show them.
  The test suite checks this.
- **Log redaction.** All stdout and stderr, including curl's own error
  messages, passes through an `awk` filter that does literal (non-regex)
  matching and replaces every configured secret with `***REDACTED***` before
  it reaches the terminal or journald. The filter gets the secrets through its
  environment, not its arguments.
- **systemd sandbox.** The service runs as the dedicated `abusechecker` user,
  whose shell is `nologin`. It uses `NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectHome`, `PrivateTmp` and `PrivateDevices`, an empty capability set,
  kernel/cgroup protections and restricted address families. The only writable
  path is `ReadWritePaths=/var/lib/abuse-checker`.
- **File permissions.** `secrets.conf` is `0600 root:root` and is read by
  systemd, not by the service user. The script refuses to source it if it is
  world-writable. State and reports are `0640` and `0750` respectively.
- **HTML safety.** Every value from the API is HTML-escaped (`@html`) before
  it goes into the report, and the report loads no external scripts or
  stylesheets.
- Only one instance runs at a time (`flock` on `/var/lib/abuse-checker/.lock`).

---

## Testing

```bash
bash tests/run_tests.sh          # KEEP_WORK=1 keeps the temp dir for inspection
```

The suite runs fully offline. It replaces `curl` with `tests/mock_curl.sh`
through the `ABUSE_CHECKER_CURL` variable, and points the config and state
directories at a temporary directory (`ABUSE_CHECKER_CONF_DIR`,
`ABUSE_CHECKER_STATE_DIR`). It covers:

- `bash -n` and `shellcheck` on every script;
- mocked responses for a clean IP, a newly dirty IP, an escalating IP, an
  unchanged dirty IP and a CIDR block, plus HTTP 429 failover and every key
  exhausted;
- state transitions `NEW` → `UNCHANGED` → `ESCALATED` (higher count and newer
  `lastReportedAt`), and dirty → clean → `NEW`;
- that no report or alert is produced when nothing changed, and
  `--force-full-report`;
- HTML validity (doctype, balanced rows, size under 30 KB, escaping, delta
  badges, links, no external resources);
- secrets: never in curl argv, always in the stdin config, scrubbed from logs
  (including simulated curl errors), and absent from state and reports;
- CIDR expansion, `--dry-run`, `--test-notify`, `--status`, `--reset-state`
  and report retention.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ABUSEIPDB_API_KEYS is not configured` | Add a key to `secrets.conf`. Run manual checks with `sudo`. |
| `IP list not readable` | Check that `ips.txt` exists and is `0644 root:abusechecker`. Re-running `install.sh` fixes the permissions. |
| `state directory ... does not exist` | Run `sudo ./install.sh`. |
| `another abuse-checker instance is running` | A run is in progress, or a stale lock is held by a running process. Check with `systemctl status abuse-checker`. |
| `API key #N rate-limited (HTTP 429)` | The daily quota is used up. Add more keys, set `REQUEST_DELAY`, or use `check-block` for ranges. |
| `API key #N rejected (HTTP 401/403)` | The key is invalid or revoked. |
| Only `ERROR` rows | Check outbound HTTPS (`curl -sI https://api.abuseipdb.com`), DNS, and the service's `RestrictAddressFamilies`. |
| Telegram `sendMessage ... failed` | The bot is not in the group or was never started in the DM, or the chat id is wrong. Groups need the `-100...` id. |
| Slack `webhook #N failed` | The webhook was revoked or the channel was archived. Regenerate the webhook. |
| Email not delivered | Check `SMTP_URL`, the port and the credentials. For Gmail, use an app password. Without `SMTP_URL`, a working local `sendmail` is required. |
| No alerts ever | That is expected while nothing changes. Check with `--force-full-report` or `--test-notify`. |
| Too many `NEW` alerts after a reset | Expected: `--reset-state` forgets history. |
| `secrets.conf` values ignored by systemd | Remove `$var` expansions and `export` keywords. Use `KEY="value"` only. |
| Corrupt `state.json` | The script logs a warning and starts fresh automatically. You can also run `--reset-state`. |

Debug a run in the foreground with the service's environment:

```bash
sudo systemd-run --pty --wait -p User=abusechecker \
  -p EnvironmentFile=/etc/abuse-checker/secrets.conf \
  -p ReadWritePaths=/var/lib/abuse-checker /usr/local/bin/abuse-checker --run
```
