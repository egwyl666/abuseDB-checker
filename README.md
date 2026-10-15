# abuse-checker

```bash
curl -fsSL https://raw.githubusercontent.com/egwyl666/abuseDB-checker/main/install.sh | sudo bash
```

**English** · [Українська](README.uk.md)

A small, dependency-light AbuseIPDB monitor for Linux servers. It is written in
plain Bash and uses only `curl`, `jq`, `awk`, `sed`, `date`, `mktemp` and
coreutils. Once a day a systemd timer checks a list of your IPs and subnets
against [AbuseIPDB](https://www.abuseipdb.com/). You only get an alert, with a
self-contained interactive HTML report, when something has changed: a newly
flagged IP or new reports against one that was already flagged.

Alerts can go to several Telegram chats, Slack webhooks and email recipients
at once. They can also open or update a Jira issue.

---

## Contents

- [How it works](#how-it-works)
- [File locations (FHS)](#file-locations-fhs)
- [Installation](#installation)
- [Configuration](#configuration)
- [Encrypted secrets](#encrypted-secrets)
- [Connectors](#connectors)
- [Managing IPs and recipients](#managing-ips-and-recipients)
- [CLI reference](#cli-reference)
- [Daily maintenance](#daily-maintenance)
- [Scheduling](#scheduling)
- [Watchdog and auto-recovery](#watchdog-and-auto-recovery)
- [System check (`--doctor`)](#system-check---doctor)
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
  **top categories**, **distinct reporters**, ISP/domain, country, last
  reported time, and a button to `https://www.abuseipdb.com/check/<IP>`;
- a **drill-down** under every dirty row (`<details>`, "View N report
  detail(s)"), plus an **Expand all / Collapse all** button next to the
  search box. The search also matches text inside the details, such as log
  comments:
  - **single IP:** usage type, hostnames and distinct reporters, then the 10
    most recent reports with timestamp (UTC), category badges, reporter
    country and the full comment or log snippet in a monospace block;
  - **CIDR:** every reported host inside the block (up to 25, worst score
    first) with score, reports, last reported time, country and its own
    AbuseIPDB link;
- automatic dark mode.

### Abuse details: categories and comments

`/api/v2/check` is called with `verbose`, so AbuseIPDB returns the individual
reports. abuse-checker keeps the details that explain the score:

| Field | From |
|-------|------|
| Usage type, hostnames, distinct reporters | `usageType`, `hostnames[]`, `numDistinctUsers` |
| Last 10 reports | `reports[]`: `reportedAt`, `comment`, categories, `reporterCountryCode` |
| Top categories | All category IDs of the reports, translated to names (`18` → Brute-Force, `22` → SSH, `14` → Port Scan, ... all 23 [AbuseIPDB categories](https://www.abuseipdb.com/categories)), most frequent first |
| Subnet hosts | `check-block` `reportedAddress[]`, top 25 by score |

Every connector tells recipients *why* an IP was flagged before they open the
report. For each `NEW` or `ESCALATED` IP it adds the categories, for example
`[Brute-Force, SSH]`, and the latest report comment, cut to 120 characters
with line breaks removed. For a subnet it shows its worst hosts instead.

| Connector | Shown as |
|-----------|----------|
| Telegram | `🏷 [Brute-Force, SSH]` and `💬 <comment>` (HTML-escaped) |
| Slack | `:label: [...]` and a `> quote` (escaped) |
| Email | `Categories: ...` and `Why: ...` lines |
| Jira | **Categories** and **Why (latest report)** columns in the table |

Comments are written by third parties and can contain anything. They are
HTML-escaped in the report and in Telegram, escaped for Slack, and have their
markup characters stripped for Jira, so a comment such as
`<script>...</script>` shows up as text.

---

## File locations (FHS)

| Path                                                   | Mode   | Owner                       | Purpose                                         |
|--------------------------------------------------------|--------|-----------------------------|-------------------------------------------------|
| `/usr/local/bin/abuse-checker`                         | `0755` | `root:root`                 | Main executable (in `$PATH`)                    |
| `/usr/local/lib/abuse-checker/connectors.d/`           | `0755` | `root:root`                 | Notification connectors (`*.sh`, run in order)  |
| `/etc/abuse-checker/secrets.conf.enc`                  | `0640` | `root:abusechecker`         | Secrets, AES-256 encrypted (OpenSSL tier)       |
| `/etc/abuse-checker/.master.key`                       | `0400` | `root:root`                 | Random 256-bit key for the OpenSSL tier         |
| `/etc/abuse-checker/secrets.cred`                      | `0600` | `root:root`                 | Secrets encrypted with `systemd-creds` (tier 1) |
| `/etc/abuse-checker/secrets.conf`                      | `0600` | `root:root`                 | *Legacy* plain text; migrate with `--encrypt-secrets` |
| `/etc/abuse-checker/secrets.conf.example`              | `0644` | `root:root`                 | Reference copy of every setting                 |
| `/etc/abuse-checker/ips.txt`                           | `0644` | `root:abusechecker`         | IPs and CIDRs to monitor                        |
| `/var/lib/abuse-checker/state.json`                    | `0640` | `abusechecker:abusechecker` | Diff state database                             |
| `/var/lib/abuse-checker/state.dryrun.json`             | `0640` | `abusechecker:abusechecker` | Separate state used by `--dry-run`              |
| `/var/lib/abuse-checker/reports/`                      | `0750` | `abusechecker:abusechecker` | Generated `.html` reports                       |
| `/etc/systemd/system/abuse-checker.service`            | `0644` | `root:root`                 | Sandboxed oneshot service                       |
| `/etc/systemd/system/abuse-checker.service.d/10-secrets.conf` | `0644` | `root:root`          | Generated: how systemd hands secrets to the service |
| `/etc/systemd/system/abuse-checker.timer`              | `0644` | `root:root`                 | Daily trigger (06:00 + up to 15 min jitter)     |
| `/etc/systemd/system/abuse-checker.timer.d/override.conf` | `0644` | `root:root`              | Custom schedule written by `--schedule`         |
| `/etc/systemd/system/abuse-checker-watchdog.service`   | `0644` | `root:root`                 | Recovery + crash alert (`--watchdog-recover`)   |
| `/etc/systemd/system/abuse-checker-watchdog.timer`     | `0644` | `root:root`                 | Periodic watchdog check (every 6 h)             |
| `/usr/local/share/doc/abuse-checker/`                  | `0755` | `root:root`                 | README files                                    |

Only one of `secrets.cred`, `secrets.conf.enc` or `secrets.conf` exists at a
time.

Repository layout:

```
abuse-checker.sh            main script (installed as /usr/local/bin/abuse-checker)
connectors/                 10-telegram.sh, 20-slack.sh, 30-email.sh, 40-jira.sh, 99-custom.sh.example
install.sh / uninstall.sh   installer (with setup wizard) and remover
systemd/                    service and timer units
config/                     secrets.conf.example, ips.txt.example
tests/run_tests.sh          offline test suite (uses tests/mock_curl.sh)
```

---

## Installation

### One-line install

```bash
curl -fsSL https://raw.githubusercontent.com/egwyl666/abuseDB-checker/main/install.sh | sudo bash
```

This downloads `install.sh`. Because there are no repository files next to it,
it fetches the tarball of the `main` branch
(`https://github.com/egwyl666/abuseDB-checker/archive/refs/heads/main.tar.gz`)
into a private `mktemp -d` directory and extracts it. It then runs `bash -n` on
every script and only installs if all of them pass. The temporary directory is
removed afterwards. The setup wizard still works, because it reads your
answers from `/dev/tty` rather than from the pipe.

Variants:

```bash
# no wizard (Ansible, cloud-init, CI)
curl -fsSL https://raw.githubusercontent.com/egwyl666/abuseDB-checker/main/install.sh | sudo bash -s -- --non-interactive
# another branch
curl -fsSL https://raw.githubusercontent.com/egwyl666/abuseDB-checker/main/install.sh | sudo AC_BRANCH=dev bash
```

If you prefer to read the script first:
`curl -fsSLO https://raw.githubusercontent.com/egwyl666/abuseDB-checker/main/install.sh && less install.sh && sudo bash install.sh`.

### From a git clone

Requirements: a systemd-based Linux with `bash` 4.4+ and `curl`. Everything
else (`jq`, `gawk`, `sed`, `openssl`, `flock` from util-linux, coreutils,
findutils, `tar`, `ca-certificates`) is **installed automatically** if
missing, using `apt-get`, `dnf`, `yum`, `apk`, `pacman` or `zypper`.
systemd 250+ is used automatically when available.

```bash
# Debian/Ubuntu
sudo apt install -y curl jq openssl
# RHEL/Alma/Rocky/Fedora
sudo dnf install -y curl jq openssl

git clone https://github.com/egwyl666/abuseDB-checker.git abuse-checker && cd abuse-checker
bash tests/run_tests.sh          # optional: run the offline test suite first
sudo ./install.sh                # creates user, dirs, units, encrypted store; enables the timer
```

`install.sh` is idempotent. It **never overwrites** existing secrets,
`ips.txt` or `state.json`; it only corrects their ownership and permissions.
Options:

- `--no-enable`: install without starting the timer;
- `--non-interactive` (`--no-wizard`, `-n`): never show the setup wizard (also skipped
  automatically when there is no TTY, e.g. in Ansible or cloud-init);
- `--upgrade-os`: run a full non-interactive system package upgrade first.
  Interactive installs ask instead:
  `Would you like to update system packages (OS upgrade) before installing? [y/N]`
  (the answer is read from `/dev/tty`, and the default is No).

Before installing anything, `install.sh` runs `abuse-checker --install-deps`.
It refreshes the package metadata and installs the missing packages without
prompting, for example `DEBIAN_FRONTEND=noninteractive apt-get install -y ...`.
If a dependency still cannot be installed, the installer stops with the
package manager's error. In one-line mode, `tar` and `gzip` are installed
first if needed, because they are required to unpack the download.

### Setup wizard

At the end of an interactive install you are asked:

```
Would you like to configure API keys and notification connectors now? [y/N]
(Tip: Press Enter or 'N' to skip and configure manually later via 'sudo abuse-checker --edit-secrets')
```

Pressing Enter skips it. If you answer `y`, it walks through four optional
steps. Press Enter at any prompt to skip that step:

1. AbuseIPDB API key(s)
2. Telegram connector (bot token + chat IDs)
3. Slack connector (webhook URLs)
4. Email connector (recipients + SMTP URL/user/password)
5. Jira connector (base URL, project key, e-mail, API token, issue type)
6. `Enable automatic updates from GitHub? [1=Notify only (default), 2=Auto-install, 3=Disabled]`

Tokens and passwords are typed without echo. Each value goes straight into the
encrypted store through `abuse-checker --set-secret` on stdin, so no plaintext
file is ever written. At the end the wizard offers to run `--test-notify`.

Then:

```bash
sudo abuse-checker --edit-secrets              # if you skipped the wizard
sudo editor /etc/abuse-checker/ips.txt
sudo abuse-checker --dry-run                   # mock data, checks the pipeline
sudo abuse-checker --test-notify               # sends a test alert to every connector
sudo systemctl start abuse-checker.service     # first real run
journalctl -u abuse-checker -n 50 --no-pager
```

> The first real run marks every dirty IP as `NEW`, so expect one larger
> alert. After that you only hear about changes.

---

## Configuration

All settings live in the encrypted secrets store (see
[Encrypted secrets](#encrypted-secrets)). Change them with
`sudo abuse-checker --edit-secrets`. Write plain `KEY="value"` or
`KEY='value'` lines only: no `$variables` and no command substitution. The
editor refuses anything else.

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
| `WATCHDOG_MAX_AGE_HOURS` | `48`         | Watchdog alerts if the last successful run is older than this    |
| `AUTO_INSTALL_DEPS`   | `true`          | Root runs (`--update` pre-step, manual `sudo` runs) install missing dependencies instead of failing |
| `AUTO_UPDATE`         | `notify`        | `notify`, `true` (auto-install) or `false`; see [Updating](#updating) |
| `REPO_SLUG` / `REPO_BRANCH` | `egwyl666/abuseDB-checker` / `main` | Source for `--check-update` and `--update`         |
| `TELEGRAM_BOT_TOKEN`  | –               | Bot token from @BotFather                                        |
| `TELEGRAM_CHAT_IDS`   | –               | Comma-separated chat ids (DMs and groups; groups are negative)   |
| `SLACK_WEBHOOK_URLS`  | –               | Comma-separated incoming webhook URLs                            |
| `EMAIL_TO`            | –               | Comma-separated recipients                                       |
| `EMAIL_FROM`          | `abuse-checker@<host>` | Sender address                                            |
| `SMTP_URL`            | –               | `smtps://host:465` or `smtp://host:587` (STARTTLS enforced)      |
| `SMTP_USER`/`SMTP_PASS` | –             | SMTP credentials. Without `SMTP_URL`, local `sendmail -t` is used |
| `JIRA_BASE_URL`            | –               | Jira base URL, e.g. `https://company.atlassian.net`             |
| `JIRA_USER_EMAIL`          | –               | Jira Cloud account e-mail (Basic auth). Empty = Server/DC PAT (Bearer) |
| `JIRA_API_TOKEN`      | –               | Cloud API token or Server/DC personal access token               |
| `JIRA_PROJECT_KEY`    | –               | Project for the issues, e.g. `SEC`                               |
| `JIRA_ISSUE_TYPE`     | `Task`          | Issue type name, e.g. `Bug`, `Incident`                          |
| `JIRA_UPDATE_MODE`    | `comment`       | `comment`: update the open issue for this host; `create`: always open a new one |
| `JIRA_LABELS` / `JIRA_PRIORITY` | –     | Extra labels (comma-separated) and priority name                 |
| `JIRA_ATTACH_REPORT`  | `true`          | Attach the HTML report to the issue                              |
| `JIRA_WATCHDOG_PRIORITY` | –            | Priority for `[WATCHDOG ALERT]` issues, e.g. `Highest`           |

The older names `JIRA_URL` and `JIRA_EMAIL` are still accepted as aliases of
`JIRA_BASE_URL` and `JIRA_USER_EMAIL`.

Free AbuseIPDB plans allow `check-block` only on networks up to `/24`. For
larger blocks, split them or use `USE_CHECK_BLOCK=false` with a smaller range.

---

## Managing IPs and recipients

### IPs and subnets

Manage the pool from the CLI. Every change is validated and written
atomically, and `ips.txt` keeps its `0644 root:abusechecker` permissions.

```bash
sudo abuse-checker --add-ip 203.0.113.10 2001:db8::1 198.51.100.0/28 --comment "web tier"
sudo abuse-checker --list-ips            # alias: --ips
sudo abuse-checker --del-ip 203.0.113.10 # alias: --rm-ip; also drops its state.json entry
sudo abuse-checker --edit-ips            # $EDITOR on a temp copy, validated on save
```

```
#    IP / SUBNET                  STATUS             COMMENT
1    203.0.113.10                 DIRTY (87%)        web tier
2    2001:db8::1                  CLEAN              web tier
3    198.51.100.0/28              UNCHECKED          web tier
4    not-an-ip                    INVALID

4 entries in /etc/abuse-checker/ips.txt
```

How each command behaves:

- **`--add-ip`** checks every argument as IPv4, IPv6 (including `::`
  compression and `::ffff:a.b.c.d`) or CIDR (`/0-32`, `/0-128`). If any
  argument is invalid, it adds **nothing** and exits non-zero, naming each bad
  value. Entries that are already present (IPv6 compared case-insensitively)
  are skipped with a message. `--comment` adds the same inline comment to
  every new line.
- **`--del-ip`** removes matching lines and deletes those targets from
  `state.json` straight away, so no stale state is left behind. It exits
  non-zero if nothing matched.
- **`--list-ips`** shows each entry's status from the last run: `CLEAN`,
  `DIRTY (score%)`, `UNCHECKED` for entries not checked yet, or `INVALID`.
- **`--edit-ips`** opens a temporary copy. When you save, it lists invalid
  entries and asks whether to edit again, save anyway or abort. Invalid
  entries that were already in the file are only noted. Without a terminal,
  it never saves new invalid entries.

You can still edit the file by hand:

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

All of these settings take comma-separated lists. Edit the encrypted store,
then check delivery:

```bash
sudo abuse-checker --edit-secrets
sudo abuse-checker --test-notify
```

An empty setting simply disables its connector. To remove a team, delete it
from the list. To add a new channel type, see [Connectors](#connectors).

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
- **Jira:** see [Jira](#jira) below.

### Jira

When an alert fires (at least one `NEW` or `ESCALATED` IP, or
`--force-full-report`), `40-jira.sh` does the following:

1. It searches for the newest **open** issue in `JIRA_PROJECT_KEY` with the
   labels `abuse-checker` and `abuse-checker-<host>`. It uses
   `/rest/api/3/search/jql` on Jira Cloud and falls back to
   `/rest/api/2/search` on Server/Data Center.
2. If one exists, it **adds a comment** to it. If not, it **creates** an issue
   with the alert title as the summary, `JIRA_ISSUE_TYPE`, the labels and an
   optional `JIRA_PRIORITY`. Set `JIRA_UPDATE_MODE="create"` to always open a
   new issue instead.
3. The description or comment is a Jira wiki table with these columns: status,
   IP/subnet, score, reports with `+delta`, ISP, country, last reported, and a
   link to the AbuseIPDB check page.
4. It attaches `report_YYYY-MM-DD.html` to the issue (set
   `JIRA_ATTACH_REPORT="false"` to skip this).

Once the issue is resolved and its status is in the Done category, the next
alert opens a fresh issue. On Jira Cloud, set `JIRA_USER_EMAIL` and an
[API token](https://id.atlassian.com/manage-profile/security/api-tokens); the
connector sends it as HTTP Basic auth. On Server/Data Center, leave
`JIRA_USER_EMAIL` empty and put a personal access token in `JIRA_API_TOKEN`; it is
sent as a Bearer token. Either way, the token and the derived `Authorization`
header only reach curl through `--config -` on stdin, and the token is
redacted from logs.

```bash
sudo abuse-checker --edit-secrets   # JIRA_BASE_URL, JIRA_USER_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY, ...
sudo abuse-checker --test-notify    # creates a "[TEST] ..." issue
```

---

## Encrypted secrets

Secrets are encrypted at rest. The tier is detected automatically when
secrets are first stored:

| Tier | When | Files | How the service gets them |
|------|------|-------|---------------------------|
| 1. `systemd-creds` | systemd ≥ 250 is running and `systemd-creds encrypt` works (TPM2 and/or host key) | `secrets.cred` | `LoadCredentialEncrypted=secrets:...`. systemd decrypts into the service's private, non-swappable credentials directory. |
| 2. OpenSSL | everywhere else | `secrets.conf.enc` + `.master.key` | `LoadCredential=master.key:...`. The service decrypts with `openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000` into memory (a pipe) and sources it. |
| Legacy | a plain `secrets.conf` you placed yourself | `secrets.conf` | `EnvironmentFile=`. Still works, but logs a warning on every run. |

The matching systemd drop-in, `abuse-checker.service.d/10-secrets.conf`, is
rewritten automatically whenever the store changes. You can force a tier with
`ABUSE_CHECKER_CRYPTO=openssl|systemd`.

```bash
sudo abuse-checker --edit-secrets      # decrypt -> /dev/shm (0600) -> $EDITOR -> validate -> re-encrypt -> shred
sudo abuse-checker --encrypt-secrets   # migrate plain secrets.conf, then shred it
printf '%s\n' "$VALUE" | sudo abuse-checker --set-secret SLACK_WEBHOOK_URLS   # scripted, value via stdin
```

How `--edit-secrets` works:

- The decrypted copy exists only as a `0600` file in `/dev/shm`, which is RAM.
  If `/dev/shm` is unavailable, the command refuses to run rather than fall
  back to disk.
- It uses `$VISUAL`, then `$EDITOR`, then `nano`, then `vi`.
- When you exit the editor, the file is checked: only comments and
  `KEY="value"` lines are allowed, and `bash -n` must pass. If the check
  fails, you can re-open the editor. If you give up, nothing changes.
- The new ciphertext is verified by decrypting it again before it replaces the
  old file. The RAM copy is then shredded, including on errors and Ctrl-C.
- If you saved without changes, nothing is re-encrypted.

Back up `.master.key` (or the host's systemd credential key) together with
`secrets.conf.enc`. Without the key the secrets cannot be recovered, and the
run aborts with `cannot decrypt` instead of running with an empty
configuration.

---

## Connectors

Notifications are delivered by modules in
`/usr/local/lib/abuse-checker/connectors.d/` (or `connectors/` when running
from a source checkout). Every `*.sh` file runs in name order, each **in its
own subshell**, so one failing connector cannot stop the others or the run.

| File | Settings |
|------|----------|
| `10-telegram.sh` | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_IDS` |
| `20-slack.sh` | `SLACK_WEBHOOK_URLS` |
| `30-email.sh` | `EMAIL_TO`, `EMAIL_FROM`, `SMTP_URL`, `SMTP_USER`, `SMTP_PASS` |
| `40-jira.sh` | `JIRA_BASE_URL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY` (required), plus `JIRA_USER_EMAIL`, `JIRA_ISSUE_TYPE`, `JIRA_UPDATE_MODE`, `JIRA_LABELS`, `JIRA_PRIORITY`, `JIRA_ATTACH_REPORT` |
| `99-custom.sh.example` | Documented template. Not loaded, because it does not end in `.sh`. |

A connector defines two functions:

```bash
connector_enabled   # return 0 when its settings are present; otherwise it is skipped silently
connector_send      # $1 = classified JSON, $2 = report.html, $3 = title; non-zero = failure (logged)
```

Files that could break a run are skipped with a warning, and the remaining
connectors still run. A file is skipped when it:

1. is empty (0 bytes) or contains only whitespace and comments;
2. fails `bash -n`;
3. does not define both `connector_enabled` and `connector_send` after being
   sourced in a test subshell.

To add a connector, run
`sudo install -m 0644 99-custom.sh.example /usr/local/lib/abuse-checker/connectors.d/40-mywebhook.sh`.
Edit it, add its settings with `--edit-secrets`, and check it with
`abuse-checker --status` (the `Connectors` line) and `--test-notify`.
Connectors can use the built-in helpers `secure_curl`, `cfg_line`,
`split_csv`, `plain_summary`, `info` and `warn`. Any setting whose name
contains `TOKEN`, `_KEY`, `PASS`, `SECRET` or `WEBHOOK` is redacted from the
logs automatically. The installer updates the bundled connectors and leaves
yours untouched.

---

## System check (`--doctor`)

```bash
sudo abuse-checker --doctor                 # alias: --check-system
sudo abuse-checker --doctor --upgrade-os    # full OS package upgrade first
```

```
[OK]    OS: Ubuntu 24.04.5 LTS (kernel 6.8.0-45-generic)
[OK]    package manager: apt-get
[FIXED] installed missing dependency: jq
[OK]    bash 5.2.21(1)-release (>= 4.4)
[OK]    curl 8.5.0
[OK]    /etc/abuse-checker/secrets.conf.enc (640 root:abusechecker)
[FIXED] /etc/abuse-checker/ips.txt: 777 root:root -> 644 root:abusechecker
[OK]    abuse-checker.timer enabled and active
[OK]    free disk space in /var/lib/abuse-checker: 30665 MB
[OK]    HTTPS to api.abuseipdb.com reachable (HTTP 401)

Summary: 15 OK, 2 fixed, 0 warning(s)
```

It checks the following:

- **System:** OS and kernel, the package manager, and versions of `bash`
  (at least 4.4), `curl`, `jq` and `openssl`.
- **Dependencies:** every required tool and the CA bundle. As root, missing
  ones are installed and reported as `[FIXED]`.
- **Files:** the service user, plus the owner and mode of every file and
  directory in [File locations](#file-locations-fhs). As root, wrong values
  are fixed. A plain-text `secrets.conf` gets a warning.
- **systemd:** `abuse-checker.timer` and the watchdog timer must be enabled
  and active, and `abuse-checker.service` must not be failed. As root, these
  are fixed.
- **Resources:** free disk space in `/var/lib/abuse-checker`, which must be
  at least 100 MB.
- **Network:** outbound HTTPS to `https://api.abuseipdb.com`. No API key is
  needed, because any HTTP answer proves the host is reachable.

The exit code is `0` when no warnings remain, so `--doctor` can be used in
monitoring. Scheduled runs repair missing dependencies too. The service's
root pre-step (`ExecStartPre=+... --auto-update`) installs anything missing,
and any manual `sudo abuse-checker` run does the same unless you set
`AUTO_INSTALL_DEPS=false`.

---

## CLI reference

```
abuse-checker [--run | --dry-run | --test-notify | --force-full-report | --status | --reset-state]
abuse-checker [--edit-secrets | --encrypt-secrets | --set-secret KEY | --uninstall [--keep|--purge]]
abuse-checker [--check-update | --update [--force]]
abuse-checker [--list-ips | --add-ip IP... [--comment T] | --del-ip IP... | --edit-ips]
abuse-checker [--schedule SPEC|show|reset | --watchdog-recover]
abuse-checker [--doctor | --check-system | --install-deps] [--upgrade-os]
```

| Flag                  | Effect |
|-----------------------|--------|
| `--run`               | Default. Run the check, update state, alert on `NEW`/`ESCALATED`. |
| `--dry-run`           | Use built-in mock API responses and a separate `state.dryrun.json`. Writes `report_<date>_dryrun.html`. Sends no notifications and makes no network calls. Uses the sample targets if `ips.txt` is not readable. |
| `--test-notify`       | Build a sample report (`report_<date>_test.html`) and send it to every configured channel. Does not touch the state. |
| `--force-full-report` | Normal run, but alerts on **every** dirty IP, including `UNCHANGED` ones. |
| `--status`            | Shows tracked IPs, dirty/clean counts, last run, report count, number of keys, the secrets store, the active connectors and the next timer trigger. |
| `--reset-state`       | Clears `state.json` (and the dry-run state). The next run treats every dirty IP as `NEW`. |
| `--edit-secrets`      | Root only. Decrypt into RAM, edit, validate, re-encrypt, shred. See [Encrypted secrets](#encrypted-secrets). |
| `--encrypt-secrets`   | Root only. Move a plain-text `secrets.conf` into the encrypted store and shred the original. |
| `--set-secret KEY`    | Root only. Set one variable, reading the value from stdin (it never appears in `ps`). |
| `--list-ips`, `--ips` | Numbered list of `ips.txt` with comments and status (`CLEAN`, `DIRTY (score%)`, `UNCHECKED`, `INVALID`). |
| `--add-ip IP\|CIDR ... [--comment TEXT]` | Root only. Validate and append entries; duplicates are skipped and nothing is added if any value is invalid. |
| `--del-ip`, `--rm-ip IP\|CIDR ...` | Root only. Remove entries from `ips.txt` and from `state.json`. |
| `--edit-ips`          | Root only. Edit `ips.txt` in `$EDITOR`, validated on save. |
| `--schedule SPEC`     | Root only. Set the run times (`"06:00,18:00"`, `every 6h`, `hourly`, an OnCalendar expression), or use `show` / `reset`. See [Scheduling](#scheduling). |
| `--watchdog-recover`  | Root only. Repair a failed service, a stale lock or an inactive timer, and alert. See [Watchdog](#watchdog-and-auto-recovery). |
| `--doctor`, `--check-system` `[--upgrade-os]` | System checklist with `[OK]`, `[WARN]` and `[FIXED]` lines; as root it installs missing dependencies and fixes permissions. See [System check](#system-check---doctor). |
| `--install-deps` `[--upgrade-os]` | Root only. Install missing dependencies (used by `install.sh`). |
| `--check-update`      | Compare the installed version with the latest on GitHub. |
| `--update`, `--self-update` | Root only. Download, verify (`bash -n`) and install the latest version (`--force` reinstalls). See [Updating](#updating). |
| `--uninstall`         | Root only. Interactive menu, or `--keep` / `--purge` for scripts. See [Uninstalling](#uninstalling). |
| `--help`, `--version` | Show usage or the version. |

When run by hand, use `sudo abuse-checker ...` so the script can decrypt the
secrets. Or let systemd run it as the service user:
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

To change when checks run, see [Scheduling](#scheduling).

---

## Scheduling

By default the check runs once a day at 06:00, with up to 15 minutes of random
delay. To change that without editing unit files:

```bash
sudo abuse-checker --schedule "06:00,14:00,22:00"   # several fixed times
sudo abuse-checker --schedule "every 6h"            # also: 6h, 12h, hourly, daily, 2x/day
sudo abuse-checker --schedule "Mon..Fri *-*-* 09:15:00"   # any systemd OnCalendar expression
sudo abuse-checker --schedule show                  # current schedule + next runs
sudo abuse-checker --schedule reset                 # back to daily 06:00
```

| Spec | OnCalendar written |
|------|--------------------|
| `06:00,18:00` | `*-*-* 06:00:00`, `*-*-* 18:00:00` |
| `hourly` / `1h` | `hourly` |
| `6h`, `every 6h` (also `2h 3h 4h 8h 12h`) | `*-*-* 00/6:00:00` |
| `daily` | `*-*-* 06:00:00` |
| `2x/day` / `4x/day` | 06:00 + 18:00 / every 6 h |
| anything else | used as-is |

Every expression is checked with `systemd-analyze calendar` before anything is
written, and invalid input changes nothing. The schedule goes into
`/etc/systemd/system/abuse-checker.timer.d/override.conf`, which starts with an
empty `OnCalendar=` to clear the default. The command then runs
`systemctl daemon-reload && systemctl restart abuse-checker.timer` and prints
the next trigger times. The setup wizard asks the same question: once a day
(default), 2x a day, 4x a day, or custom times. Updates never overwrite your
override.

---

## Watchdog and auto-recovery

`abuse-checker.service` recovers on its own:

| Setting | Effect |
|---------|--------|
| `TimeoutStartSec=15min`, `RuntimeMaxSec=15min` | A run that hangs for 15 minutes is killed. A `Type=oneshot` run counts as starting until it exits, so `TimeoutStartSec` is the limit that actually applies. |
| `Restart=on-failure`, `RestartSec=60s` | A crashed or killed run is retried after 60 s. |
| `StartLimitIntervalSec=15min`, `StartLimitBurst=3` | At most 3 starts per 15 minutes. After that the unit is marked failed... |
| `OnFailure=abuse-checker-watchdog.service` | ...and the watchdog starts. |

`abuse-checker-watchdog.service` runs `abuse-checker --watchdog-recover` as
root. It is started by `OnFailure=`, and also every 6 hours by
`abuse-checker-watchdog.timer`. It:

1. resets the failed state of `abuse-checker.service`;
2. removes `/var/lib/abuse-checker/.lock` if no process holds it (a held lock
   means a run is in progress, so it is left alone);
3. makes sure `abuse-checker.timer` is enabled and active, and restarts it if
   not;
4. checks that the last successful run is less than `WATCHDOG_MAX_AGE_HOURS`
   (default 48) old;
5. if anything was wrong, sends a high-priority
   **`[WATCHDOG ALERT] abuse-checker on <host> crashed and was recovered`** to
   every configured connector. The alert lists the problems, the recovery
   actions taken, and the last 15 lines of
   `journalctl -u abuse-checker.service` with secrets redacted.

How each connector delivers the watchdog alert:

- **Telegram:** a 🚨 message with the log in a `<pre>` block.
- **Slack:** a `:rotating_light:` header with the log in a code block.
- **Email:** sent with `X-Priority: 1` and `Importance: high`.
- **Jira:** always a **new** issue, labelled `abuse-checker-watchdog`, with
  priority `JIRA_WATCHDOG_PRIORITY` if you set one.

A healthy system produces no alert.

```bash
sudo abuse-checker --watchdog-recover           # run the check by hand
systemctl list-timers abuse-checker-watchdog.timer
journalctl -u abuse-checker-watchdog -n 30
```

---

## Updating

The upstream repository is
[`egwyl666/abuseDB-checker`](https://github.com/egwyl666/abuseDB-checker),
branch `main`.

```bash
sudo abuse-checker --check-update    # installed vs latest version on GitHub
sudo abuse-checker --update          # same as --self-update; add --force to reinstall
```

`--update` works like this:

1. It downloads the branch tarball into a private temporary directory.
2. It runs `bash -n` on the downloaded `abuse-checker.sh`, `install.sh` and
   every connector, and reads the new `AC_VERSION`. If any check fails, it
   stops **before touching the system**, and the installed version keeps
   working.
3. It runs the new `install.sh --no-wizard`. That replaces the binary
   atomically and refreshes the connectors and systemd units. Your secrets,
   `ips.txt`, `state.json`, reports and custom connectors are kept.

The one-line installer does the same job and is safe to re-run. From a clone,
you can still use `git pull && sudo ./install.sh`.

### Automatic updates (`AUTO_UPDATE`)

Set this with `sudo abuse-checker --edit-secrets`, or in the setup wizard.

| Value | Behaviour |
|-------|-----------|
| `notify` (default) | Once a day during the scheduled run, it checks GitHub; the result is cached in `/var/lib/abuse-checker/update-check.json`. If a newer version exists, it logs it and adds `Update available: vX.Y.Z -> Run 'sudo abuse-checker --update'` to the HTML report, the Telegram and Slack footers and the email body. |
| `true` | Before the daily check, `ExecStartPre=-+/usr/local/bin/abuse-checker --auto-update` runs as root, outside the sandbox, and applies a newer version with the same verification as `--update`. A failed or rejected update is logged and never blocks the check. |
| `false` | Scheduled runs never contact GitHub. |

`REPO_SLUG` and `REPO_BRANCH` can point the updater at a fork or another
branch. `abuse-checker --status` shows the current policy and the latest
version it has seen.

If you upgrade from 1.0 with a plain `secrets.conf`, finish with
`sudo abuse-checker --encrypt-secrets`. To check for new settings, compare
`/etc/abuse-checker/secrets.conf.example` with
`sudo abuse-checker --edit-secrets`.

---

## Uninstalling

```bash
sudo abuse-checker --uninstall           # interactive menu
sudo abuse-checker --uninstall --keep    # scripted: same as option [1]
sudo abuse-checker --uninstall --purge   # scripted: same as option [2]
sudo ./uninstall.sh [--keep|--purge]     # same thing, from the source checkout
```

The interactive menu lists every path that would be removed, with its size:

```
  [1] Remove application & systemd timer only (KEEP encrypted secrets, ips.txt, and HTML reports)
      Removes:
      /usr/local/bin/abuse-checker                            48K
      /usr/local/lib/abuse-checker                            24K
      ...
  [2] Full Purge (Remove everything including /etc/abuse-checker, /var/lib/abuse-checker, and the 'abusechecker' user)
      Additionally removes:
      /etc/abuse-checker                                      20K
      /var/lib/abuse-checker                                  12K
  [3] Cancel
```

The default is `[3] Cancel`. A purge must be confirmed by typing `purge`, and
it shreds the master key and any plain-text secrets before deleting the
directories. Without a TTY the command refuses to guess; pass `--keep` or
`--purge`.

---

## Security model

- **Encrypted at rest.** Secrets are stored with `systemd-creds` or AES-256
  (OpenSSL, PBKDF2 with 100,000 iterations, random 256-bit key). Plaintext
  only exists in pipes, in process memory, or in a shredded `0600` file in
  `/dev/shm` while you edit. The key is passed to openssl as `-pass file:` and
  never on the command line. See [Encrypted secrets](#encrypted-secrets).
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
- **File permissions.** `.master.key` is `0400 root:root` and
  `secrets.cred` is `0600 root:root`. systemd reads both as root and hands
  them to the service through its private credentials directory. A legacy
  plain `secrets.conf` must be `0600`, and the script refuses to source it if
  it is world-writable. State and reports are `0640` and `0750` respectively.
- **Verified updates.** Updates come only from the configured GitHub
  repository over HTTPS. They are unpacked in a private temp directory and
  syntax-checked before anything is installed. The only step that runs as
  root outside the sandbox is the `AUTO_UPDATE=true` pre-step (`+` prefix).
  It does nothing unless that mode is on. Use `notify` if you want to review
  changes yourself.
- **Isolated connectors.** Each connector runs in its own subshell, after
  syntax and interface checks.
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
`ABUSE_CHECKER_STATE_DIR`, `ABUSE_CHECKER_CONNECTORS_DIR`,
`ABUSE_CHECKER_RAMDIR`, `ABUSE_CHECKER_DROPIN_DIR`). It covers:

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
  and report retention;
- connectors: loading from `connectors.d`; a 0-byte file, a whitespace- or
  comment-only file, a syntax error, a missing interface, a failing connector
  and a disabled connector each give a warning or a silent skip while the other
  connectors still deliver; a custom connector built from the template;
  comment-only `ips.txt` and empty connector settings;
- encryption: `--encrypt-secrets` migration (salt header, 64-hex master key,
  `0400`/`0640` modes, round trip, drop-in); running from the encrypted store;
  loading through `CREDENTIALS_DIRECTORY`; `--set-secret` through stdin;
  `--edit-secrets` (the RAM file is `0600`, the edit is re-encrypted,
  invalid edits are rejected, unchanged edits are a no-op, the RAM file is
  shredded); a wrong master key aborts; openssl never sees a secret in argv;
  no plaintext secret is left in the config, state, RAM or tmp directories;
  and the `systemd-creds` tier when available;
- Jira: an issue is created with the right payload (project, issue type,
  priority, labels including the host label, summary, wiki table with
  `+delta` and AbuseIPDB links, ISP text) and the report is attached; an open
  issue gets a comment instead of a duplicate; the Server/DC fallback to
  `/rest/api/2/search` and Bearer PAT; `JIRA_UPDATE_MODE=create`; a Jira API
  error is surfaced while other connectors still deliver; Jira is skipped when
  not configured; `--test-notify` reaches it; the token and the Basic header
  never appear in argv and the token is redacted from logs;
- Jira with `JIRA_BASE_URL`/`JIRA_USER_EMAIL`: `POST /rest/api/2/issue` with
  project, issue type and summary table; the HTML report uploaded to
  `/attachments` with `X-Atlassian-Token: no-check`; Basic auth; the token
  never in argv and redacted from output;
- IP pool: `--add-ip` with IPv4, IPv6 (compressed, embedded IPv4) and CIDR,
  inline comments, `0644` kept, duplicate detection (IPv6 case-insensitive),
  all-or-nothing rejection of `999.1.1.1`, `/33`, `:::`, `hello` and `/129`;
  `--list-ips` statuses, comments and numbering; `--del-ip` and `--rm-ip`
  removing entries from `ips.txt` and `state.json` and reporting `not found`;
  `--edit-ips` saving valid edits, refusing new invalid entries without a
  TTY, and cleaning up its temp file;
- `--schedule`: the drop-in contents for `"06:00,18:00"`, `"7:05, 22:30"`,
  `every 6h`, `6h`, `every 12h`, `hourly`, `daily` and `2x/day`; rejection of
  `7h`, `25:00` and invalid raw expressions (via `systemd-analyze`); raw
  OnCalendar; `daemon-reload` and timer restart; `show` and `reset`;
- abuse details: category map (`18` → Brute-Force, `22` → SSH, all of
  1..23); `norm_check` ordering by frequency and newest report, plus
  metadata; `norm_block` host sorting; the report's new columns, badges,
  `<details>` for IPs and subnets, sub-tables, newest-first order, escaping
  of `<script>` / `&` / quotes in comments, the Expand all button, balanced
  tags and size; categories and the 120-character snippet in Telegram,
  Slack, email and Jira; `--dry-run` mocks carrying verbose reports;
- `--doctor` / `--check-system` with a fake package manager: OS line,
  install of the mapped packages with `[FIXED]`, version checks, a mode fix
  (`777` → `644`), plain-text secrets warning, systemd checks, disk space,
  HTTPS reachability, summary and exit code, `--upgrade-os`, a failed
  install giving `[WARN]`; `--install-deps` package mapping for `dnf`, `yum`,
  `apk`, `pacman` and `zypper`; the runtime root fallback and
  `AUTO_INSTALL_DEPS=false`;
- watchdog: a healthy system sends no alert; a failed service, a stale lock
  and an inactive or disabled timer are repaired and alerted on Telegram,
  Slack, email (high priority) and Jira (new issue, watchdog label and
  priority); the 15 journal lines are included with secrets redacted; a held
  lock is left alone; a stale `lastRun` raises an alert; the unit settings
  are checked and the units pass `systemd-analyze verify`;
- self-update: `--check-update` (newer, same, unreachable); `--update` with
  a good release, a corrupted `abuse-checker.sh`, a corrupted connector, a
  garbage archive and a failed download (each rejected, with the installed
  binary byte-for-byte unchanged); same-version and `--force`;
  `AUTO_UPDATE=notify` (banner in the report, Telegram, Slack and email, one
  check per day), `false` (no GitHub request) and `true` (`--auto-update`
  installs, and a corrupted update never fails the service); the piped
  `install.sh` bootstrap (download, verify, reject, clean up);
- `--uninstall` in a fake root: the menu text and paths, cancel, `[1]`,
  `[2]` with and without typed confirmation, refusal without a TTY, and the
  `uninstall.sh` wrapper.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ABUSEIPDB_API_KEYS is not configured` | Add a key with `sudo abuse-checker --edit-secrets`. Run manual checks with `sudo`. |
| `secrets are encrypted but the master key is not readable` | Run with `sudo`, or through systemd (`systemctl start abuse-checker`). |
| `cannot decrypt ... (wrong or missing master key?)` | `.master.key` does not match `secrets.conf.enc`. Restore both from backup, or remove the `.enc` file and re-enter the secrets with `--edit-secrets`. |
| `secrets are stored in plain text` | Run `sudo abuse-checker --encrypt-secrets`. |
| `RAM directory /dev/shm not available` | Mount tmpfs on `/dev/shm`, or set `ABUSE_CHECKER_RAMDIR` to another tmpfs directory. |
| `connector X: ... skipped` | That file in `connectors.d` is empty, has a syntax error, or lacks `connector_enabled`/`connector_send`. Fix or delete it. |
| `Jira issue creation failed (HTTP 400): ...` | Jira's own error is shown, often a wrong `JIRA_ISSUE_TYPE` or a required field such as a component. Fix it with `--edit-secrets`, then retry with `--test-notify`. |
| `Jira ... (HTTP 401/403)` | Wrong `JIRA_USER_EMAIL` or token, or the account cannot create issues in the project. On Server/DC, leave `JIRA_USER_EMAIL` empty to use a PAT. |
| `error: invalid IP/CIDR: ...` from `--add-ip` | Nothing was added. Fix or remove the listed value, for example `/33` or `999.x`, and run the command again. |
| `invalid OnCalendar expression` | Test the expression with `systemd-analyze calendar '<expr>'`, or use one of the presets. |
| `[WATCHDOG ALERT]` received | The service failed 3 times within 15 minutes, or hung. Read the log lines in the alert and `journalctl -u abuse-checker -n 100`. Recovery has already run, and the next timer run retries. |
| `start request repeated too quickly` | The start limit (3 per 15 minutes) was hit. The watchdog resets it, or run `sudo systemctl reset-failed abuse-checker`. |
| `missing dependencies: ... (run: sudo abuse-checker --doctor)` | Run `sudo abuse-checker --doctor`; it installs what is missing. If that fails, check the package manager's error (offline mirror, held packages). |
| `--doctor`: `cannot reach https://api.abuseipdb.com` | DNS, firewall or proxy is blocking outbound HTTPS. Test with `curl -sI https://api.abuseipdb.com`. |
| Report row has no "View ... detail(s)" | That IP has no reports in the window, or it is clean. Subnets list hosts only when AbuseIPDB returned some. |
| `no connector delivered the alert` | No connector is configured. Run `--status` and check the `Connectors` line, then `--edit-secrets`. |
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
| `update check failed: HTTP ...` | GitHub is unreachable, or `REPO_SLUG`/`REPO_BRANCH` is wrong. The check runs again the next day, and nothing else is affected. |
| `... fails 'bash -n'; update rejected` | The upstream branch is broken. Your installed version keeps running. Try again later or pin `REPO_BRANCH`. |
| `curl ... install.sh \| sudo bash` returns 404 | The `main` branch does not exist (yet). Use `sudo AC_BRANCH=<branch> bash`. |
| `--edit-secrets` reports `invalid line(s)` | Use `KEY="value"` or `KEY='value'`, with no `$(...)`, backticks or `;`. |
| Corrupt `state.json` | The script logs a warning and starts fresh automatically. You can also run `--reset-state`. |

Debug a run in the foreground with the service's environment:

```bash
sudo systemd-run --pty --wait -p User=abusechecker \
  -p LoadCredential=master.key:/etc/abuse-checker/.master.key \
  -p ReadWritePaths=/var/lib/abuse-checker /usr/local/bin/abuse-checker --run
```
