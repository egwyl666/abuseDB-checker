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
at once.

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
| `/usr/local/share/doc/abuse-checker/`                  | `0755` | `root:root`                 | README files                                    |

Only one of `secrets.cred`, `secrets.conf.enc` or `secrets.conf` exists at a
time.

Repository layout:

```
abuse-checker.sh            main script (installed as /usr/local/bin/abuse-checker)
connectors/                 10-telegram.sh, 20-slack.sh, 30-email.sh, 99-custom.sh.example
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

Requirements: a systemd-based Linux, Bash 4.4+, `curl` 7.55+, `jq` 1.6+,
`tar` and `openssl` (systemd 250+ is used automatically when available).

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
  automatically when there is no TTY, e.g. in Ansible or cloud-init).

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
5. `Enable automatic updates from GitHub? [1=Notify only (default), 2=Auto-install, 3=Disabled]`

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
| `AUTO_UPDATE`         | `notify`        | `notify`, `true` (auto-install) or `false`; see [Updating](#updating) |
| `REPO_SLUG` / `REPO_BRANCH` | `egwyl666/abuseDB-checker` / `main` | Source for `--check-update` and `--update`         |
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

## CLI reference

```
abuse-checker [--run | --dry-run | --test-notify | --force-full-report | --status | --reset-state]
abuse-checker [--edit-secrets | --encrypt-secrets | --set-secret KEY | --uninstall [--keep|--purge]]
abuse-checker [--check-update | --update [--force]]
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

To change the schedule, run `sudo systemctl edit abuse-checker.timer` and add:

```ini
[Timer]
OnCalendar=
OnCalendar=*-*-* 07:30:00
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
