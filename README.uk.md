# abuse-checker

```bash
curl -fsSL https://raw.githubusercontent.com/egwyl666/abuseDB-checker/main/install.sh | sudo bash
```

[English](README.md) · **Українська**

Невеликий монітор AbuseIPDB для Linux-серверів із мінімумом залежностей.
Написаний на чистому Bash і використовує лише `curl`, `jq`, `awk`, `sed`,
`date`, `mktemp` та coreutils. Раз на день таймер systemd перевіряє список
ваших IP-адрес і підмереж в [AbuseIPDB](https://www.abuseipdb.com/). Сповіщення
з автономним інтерактивним HTML-звітом надходить лише тоді, коли щось
змінилося: з'явилася нова позначена IP-адреса або нові скарги на вже
позначену.

Сповіщення можна надсилати одночасно в кілька чатів Telegram, вебхуків Slack
та на кілька адрес електронної пошти. Також вони можуть створювати або
оновлювати задачу в Jira.

---

## Зміст

- [Як це працює](#як-це-працює)
- [Розташування файлів (FHS)](#розташування-файлів-fhs)
- [Встановлення](#встановлення)
- [Налаштування](#налаштування)
- [Зашифровані секрети](#зашифровані-секрети)
- [Конектори](#конектори)
- [Керування IP-адресами та отримувачами](#керування-ip-адресами-та-отримувачами)
- [Довідка CLI](#довідка-cli)
- [Щоденне обслуговування](#щоденне-обслуговування)
- [Розклад](#розклад)
- [Watchdog і автовідновлення](#watchdog-і-автовідновлення)
- [Оновлення](#оновлення)
- [Видалення](#видалення)
- [Модель безпеки](#модель-безпеки)
- [Тестування](#тестування)
- [Усунення несправностей](#усунення-несправностей)

---

## Як це працює

1. Читає `/etc/abuse-checker/ips.txt`. Окремі IP-адреси (IPv4 або IPv6)
   перевіряються запитом `GET /api/v2/check?maxAgeInDays=30&verbose`.
   CIDR-блоки перевіряються через `GET /api/v2/check-block`. Якщо встановити
   `USE_CHECK_BLOCK=false`, невеликі IPv4-блоки (до `EXPAND_MAX_HOSTS` адрес)
   натомість розгортаються і перевіряються по одній IP-адресі.
2. Кожен результат порівнюється з `/var/lib/abuse-checker/state.json`.
   IP-адреса вважається **брудною**, якщо `abuseConfidenceScore > THRESHOLD`
   або `totalReports > 0`.

   | Статус      | Значення                                                                          |
   |-------------|-----------------------------------------------------------------------------------|
   | `CLEAN`     | Не брудна                                                                         |
   | `NEW`       | Брудна зараз, але була чистою або невідомою під час попередньої перевірки         |
   | `ESCALATED` | Вже була брудною, і `totalReports` зросло **або** `lastReportedAt` новіший        |
   | `UNCHANGED` | Досі брудна, нових скарг з попередньої перевірки немає                            |
   | `ERROR`     | Запит до API не вдався. Попередній стан цієї IP-адреси зберігається.              |

   Для CIDR оцінкою вважається найвища оцінка в блоці, скарги підсумовуються
   по всьому блоку, а `lastReportedAt` — це найсвіжіша скарга.
3. **Правило сповіщень:** звіт створюється і сповіщення надсилаються **лише
   якщо є хоча б одна IP-адреса зі статусом `NEW` або `ESCALATED`**. Виняток —
   `--force-full-report`, який сповіщає про всі брудні IP-адреси. Кількість
   `UNCHANGED` IP-адрес показується в нижньому колонтитулі.
4. Файл стану записується атомарно. Звіти, старші за `RETENTION_DAYS`,
   видаляються.

### API-ключі та перемикання

`ABUSEIPDB_API_KEYS="key1,key2,..."`. Перевірка використовує перший ключ,
доки не станеться одне з наступного:

- він повертає HTTP `429`, `401` або `403`;
- відповідь містить `X-RateLimit-Remaining: 0`.

Тоді вона переходить до наступного ключа. Якщо всі ключі вичерпано, IP-адреси,
які не встигли перевірити, зберігають попередній стан і будуть перевірені під
час наступного запуску. У логах ключі згадуються лише як `key #N`.

### HTML-звіт

Звіт зберігається як `/var/lib/abuse-checker/reports/report_YYYY-MM-DD.html`.
Це один файл із вбудованим CSS і близько 1 КБ чистого JS, який нічого не
завантажує ззовні (приблизно 6–15 КБ для типового списку). Він містить:

- картки підсумків: усього перевірено, чисті, нові, ескальовані, незмінні
  брудні, помилки;
- таблицю з фільтром і сортуванням за кліком на заголовок стовпця. Стовпці:
  значок статусу, IP/підмережа, кольорова оцінка, загальна кількість скарг зі
  значком `+delta`, ISP/домен, країна, час останньої скарги та кнопка на
  `https://www.abuseipdb.com/check/<IP>`;
- автоматичну темну тему.

---

## Розташування файлів (FHS)

| Шлях                                                   | Права  | Власник                     | Призначення                                        |
|--------------------------------------------------------|--------|-----------------------------|----------------------------------------------------|
| `/usr/local/bin/abuse-checker`                         | `0755` | `root:root`                 | Основний виконуваний файл (у `$PATH`)              |
| `/usr/local/lib/abuse-checker/connectors.d/`           | `0755` | `root:root`                 | Конектори сповіщень (`*.sh`, виконуються по черзі) |
| `/etc/abuse-checker/secrets.conf.enc`                  | `0640` | `root:abusechecker`         | Секрети, зашифровані AES-256 (рівень OpenSSL)      |
| `/etc/abuse-checker/.master.key`                       | `0400` | `root:root`                 | Випадковий 256-бітний ключ для рівня OpenSSL       |
| `/etc/abuse-checker/secrets.cred`                      | `0600` | `root:root`                 | Секрети, зашифровані `systemd-creds` (рівень 1)    |
| `/etc/abuse-checker/secrets.conf`                      | `0600` | `root:root`                 | *Застарілий* відкритий текст; перенесіть через `--encrypt-secrets` |
| `/etc/abuse-checker/secrets.conf.example`              | `0644` | `root:root`                 | Довідкова копія всіх налаштувань                   |
| `/etc/abuse-checker/ips.txt`                           | `0644` | `root:abusechecker`         | IP-адреси та CIDR для моніторингу                  |
| `/var/lib/abuse-checker/state.json`                    | `0640` | `abusechecker:abusechecker` | База даних стану для порівняння                    |
| `/var/lib/abuse-checker/state.dryrun.json`             | `0640` | `abusechecker:abusechecker` | Окремий стан для `--dry-run`                       |
| `/var/lib/abuse-checker/reports/`                      | `0750` | `abusechecker:abusechecker` | Згенеровані `.html`-звіти                          |
| `/etc/systemd/system/abuse-checker.service`            | `0644` | `root:root`                 | Ізольований oneshot-сервіс                         |
| `/etc/systemd/system/abuse-checker.service.d/10-secrets.conf` | `0644` | `root:root`          | Генерується: як systemd передає секрети сервісу    |
| `/etc/systemd/system/abuse-checker.timer`              | `0644` | `root:root`                 | Щоденний запуск (06:00 + до 15 хв випадково)       |
| `/etc/systemd/system/abuse-checker.timer.d/override.conf` | `0644` | `root:root`              | Власний розклад, записаний через `--schedule`      |
| `/etc/systemd/system/abuse-checker-watchdog.service`   | `0644` | `root:root`                 | Відновлення + сповіщення про збій (`--watchdog-recover`) |
| `/etc/systemd/system/abuse-checker-watchdog.timer`     | `0644` | `root:root`                 | Періодична перевірка watchdog (кожні 6 год)        |
| `/usr/local/share/doc/abuse-checker/`                  | `0755` | `root:root`                 | Файли README                                       |

Одночасно існує лише один із файлів `secrets.cred`, `secrets.conf.enc` або
`secrets.conf`.

Структура репозиторію:

```
abuse-checker.sh            основний скрипт (встановлюється як /usr/local/bin/abuse-checker)
connectors/                 10-telegram.sh, 20-slack.sh, 30-email.sh, 40-jira.sh, 99-custom.sh.example
install.sh / uninstall.sh   встановлення (з майстром налаштування) та видалення
systemd/                    юніти сервісу й таймера
config/                     secrets.conf.example, ips.txt.example
tests/run_tests.sh          офлайн-набір тестів (використовує tests/mock_curl.sh)
```

---

## Встановлення

### Встановлення однією командою

```bash
curl -fsSL https://raw.githubusercontent.com/egwyl666/abuseDB-checker/main/install.sh | sudo bash
```

Команда завантажує `install.sh`. Поруч із ним немає файлів репозиторію, тому
він завантажує архів гілки `main`
(`https://github.com/egwyl666/abuseDB-checker/archive/refs/heads/main.tar.gz`)
у приватний каталог `mktemp -d` і розпаковує його. Потім виконує `bash -n` для
кожного скрипта і встановлює лише тоді, коли всі перевірки пройдено.
Тимчасовий каталог після цього видаляється. Майстер налаштування теж працює,
бо читає відповіді з `/dev/tty`, а не з каналу.

Варіанти:

```bash
# без майстра (Ansible, cloud-init, CI)
curl -fsSL https://raw.githubusercontent.com/egwyl666/abuseDB-checker/main/install.sh | sudo bash -s -- --non-interactive
# інша гілка
curl -fsSL https://raw.githubusercontent.com/egwyl666/abuseDB-checker/main/install.sh | sudo AC_BRANCH=dev bash
```

Якщо хочете спочатку переглянути скрипт:
`curl -fsSLO https://raw.githubusercontent.com/egwyl666/abuseDB-checker/main/install.sh && less install.sh && sudo bash install.sh`.

### Із git clone

Вимоги: Linux із systemd, Bash 4.4+, `curl` 7.55+, `jq` 1.6+, `tar` та
`openssl` (systemd 250+ використовується автоматично, якщо доступний).

```bash
# Debian/Ubuntu
sudo apt install -y curl jq openssl
# RHEL/Alma/Rocky/Fedora
sudo dnf install -y curl jq openssl

git clone https://github.com/egwyl666/abuseDB-checker.git abuse-checker && cd abuse-checker
bash tests/run_tests.sh          # необов'язково: спочатку запустити офлайн-тести
sudo ./install.sh                # створює користувача, каталоги, юніти, зашифроване сховище; вмикає таймер
```

`install.sh` ідемпотентний. Він **ніколи не перезаписує** наявні секрети,
`ips.txt` чи `state.json`, лише виправляє їхніх власників і права доступу.
Параметри:

- `--no-enable`: встановити без запуску таймера;
- `--non-interactive` (`--no-wizard`, `-n`): ніколи не показувати майстер налаштування
  (він також автоматично пропускається без TTY, наприклад в Ansible чи
  cloud-init).

### Майстер налаштування

Наприкінці інтерактивного встановлення з'являється запитання:

```
Would you like to configure API keys and notification connectors now? [y/N]
(Tip: Press Enter or 'N' to skip and configure manually later via 'sudo abuse-checker --edit-secrets')
```

Натисніть Enter, щоб пропустити його. Якщо відповісти `y`, майстер проведе
через чотири необов'язкові кроки. Натисніть Enter на будь-якому запитанні,
щоб пропустити цей крок:

1. API-ключ(і) AbuseIPDB
2. Конектор Telegram (токен бота + ідентифікатори чатів)
3. Конектор Slack (URL вебхуків)
4. Конектор Email (отримувачі + URL/користувач/пароль SMTP)
5. Конектор Jira (базовий URL, ключ проєкту, e-mail, API-токен, тип задачі)
6. `Enable automatic updates from GitHub? [1=Notify only (default), 2=Auto-install, 3=Disabled]` — автоматичні оновлення з GitHub: 1 — лише сповіщати (типово), 2 — встановлювати автоматично, 3 — вимкнено

Токени й паролі вводяться без відображення. Кожне значення одразу потрапляє в
зашифроване сховище через `abuse-checker --set-secret` (через stdin), тож
жоден файл із відкритим текстом не створюється. Наприкінці майстер пропонує
запустити `--test-notify`.

Далі:

```bash
sudo abuse-checker --edit-secrets              # якщо ви пропустили майстер
sudo editor /etc/abuse-checker/ips.txt
sudo abuse-checker --dry-run                   # тестові дані, перевірка всього ланцюжка
sudo abuse-checker --test-notify               # тестове сповіщення в усі конектори
sudo systemctl start abuse-checker.service     # перший реальний запуск
journalctl -u abuse-checker -n 50 --no-pager
```

> Під час першого реального запуску всі брудні IP-адреси позначаються як
> `NEW`, тож очікуйте одне більше сповіщення. Надалі ви отримуватимете лише
> повідомлення про зміни.

---

## Налаштування

Усі налаштування зберігаються в зашифрованому сховищі секретів (див.
[Зашифровані секрети](#зашифровані-секрети)). Змінюйте їх командою
`sudo abuse-checker --edit-secrets`. Пишіть лише прості рядки `KEY="value"`
або `KEY='value'`: без `$змінних` і без підстановки команд. Інше редактор не
прийме.

| Змінна                | Типово          | Опис                                                                |
|-----------------------|-----------------|---------------------------------------------------------------------|
| `ABUSEIPDB_API_KEYS`  | –               | API-ключі через кому; перемикання по черзі                          |
| `THRESHOLD`           | `25`            | Оцінка, вище якої IP-адреса вважається брудною                      |
| `MAX_AGE_DAYS`        | `30`            | `maxAgeInDays`, що передається в API                                |
| `USE_CHECK_BLOCK`     | `true`          | `false` = розгортати малі IPv4 CIDR і перевіряти кожну IP           |
| `EXPAND_MAX_HOSTS`    | `256`           | Найбільший CIDR для розгортання при `USE_CHECK_BLOCK=false`         |
| `REQUEST_DELAY`       | `0`             | Пауза в секундах між запитами до API                                |
| `RETENTION_DAYS`      | `30`            | Видаляти звіти, старші за цю кількість днів                         |
| `HOST_LABEL`          | ім'я хоста      | Назва, що показується в сповіщеннях і звітах                        |
| `WATCHDOG_MAX_AGE_HOURS` | `48`         | Watchdog надсилає сповіщення, якщо останній успішний запуск давніший за цей час |
| `AUTO_UPDATE`         | `notify`        | `notify`, `true` (автовстановлення) або `false`; див. [Оновлення](#оновлення) |
| `REPO_SLUG` / `REPO_BRANCH` | `egwyl666/abuseDB-checker` / `main` | Джерело для `--check-update` і `--update`          |
| `TELEGRAM_BOT_TOKEN`  | –               | Токен бота від @BotFather                                           |
| `TELEGRAM_CHAT_IDS`   | –               | Ідентифікатори чатів через кому (особисті й групи; у груп від'ємні) |
| `SLACK_WEBHOOK_URLS`  | –               | URL вхідних вебхуків через кому                                     |
| `EMAIL_TO`            | –               | Отримувачі через кому                                               |
| `EMAIL_FROM`          | `abuse-checker@<host>` | Адреса відправника                                           |
| `SMTP_URL`            | –               | `smtps://host:465` або `smtp://host:587` (STARTTLS обов'язковий)    |
| `SMTP_USER`/`SMTP_PASS` | –             | Облікові дані SMTP. Без `SMTP_URL` використовується локальний `sendmail -t` |
| `JIRA_BASE_URL`            | –               | Базовий URL Jira, наприклад `https://company.atlassian.net`        |
| `JIRA_USER_EMAIL`          | –               | E-mail облікового запису Jira Cloud (Basic auth). Порожньо = PAT для Server/DC (Bearer) |
| `JIRA_API_TOKEN`      | –               | API-токен Cloud або персональний токен доступу Server/DC            |
| `JIRA_PROJECT_KEY`    | –               | Проєкт для задач, наприклад `SEC`                                   |
| `JIRA_ISSUE_TYPE`     | `Task`          | Назва типу задачі, наприклад `Bug`, `Incident`                      |
| `JIRA_UPDATE_MODE`    | `comment`       | `comment`: оновити відкриту задачу для цього хоста; `create`: щоразу створювати нову |
| `JIRA_LABELS` / `JIRA_PRIORITY` | –     | Додаткові мітки (через кому) та назва пріоритету                    |
| `JIRA_ATTACH_REPORT`  | `true`          | Прикріпити HTML-звіт до задачі                                      |
| `JIRA_WATCHDOG_PRIORITY` | –            | Пріоритет задач `[WATCHDOG ALERT]`, наприклад `Highest`             |

Старі назви `JIRA_URL` і `JIRA_EMAIL` і далі приймаються як синоніми
`JIRA_BASE_URL` і `JIRA_USER_EMAIL`.

Безкоштовні тарифи AbuseIPDB дозволяють `check-block` лише для мереж до `/24`.
Більші блоки розділіть або використайте `USE_CHECK_BLOCK=false` з меншим
діапазоном.

---

## Керування IP-адресами та отримувачами

### IP-адреси та підмережі

Керуйте списком із командного рядка. Кожна зміна перевіряється й
записується атомарно, а `ips.txt` зберігає права `0644 root:abusechecker`.

```bash
sudo abuse-checker --add-ip 203.0.113.10 2001:db8::1 198.51.100.0/28 --comment "web tier"
sudo abuse-checker --list-ips            # синонім: --ips
sudo abuse-checker --del-ip 203.0.113.10 # синонім: --rm-ip; також видаляє запис зі state.json
sudo abuse-checker --edit-ips            # $EDITOR на тимчасовій копії, перевірка при збереженні
```

```
#    IP / SUBNET                  STATUS             COMMENT
1    203.0.113.10                 DIRTY (87%)        web tier
2    2001:db8::1                  CLEAN              web tier
3    198.51.100.0/28              UNCHECKED          web tier
4    not-an-ip                    INVALID

4 entries in /etc/abuse-checker/ips.txt
```

Як працює кожна команда:

- **`--add-ip`** перевіряє кожен аргумент як IPv4, IPv6 (зокрема зі
  скороченням `::` і формою `::ffff:a.b.c.d`) або CIDR (`/0-32`, `/0-128`).
  Якщо хоча б один аргумент некоректний, вона **нічого не додає**, завершується
  з ненульовим кодом і називає кожне хибне значення. Записи, які вже є у
  файлі (IPv6 порівнюються без урахування регістру), пропускаються з
  повідомленням. `--comment` додає однаковий коментар до кожного нового
  рядка.
- **`--del-ip`** видаляє відповідні рядки й одразу прибирає ці записи зі
  `state.json`, тож застарілого стану не лишається. Якщо нічого не знайдено,
  завершується з ненульовим кодом.
- **`--list-ips`** показує стан кожного запису після останнього запуску:
  `CLEAN`, `DIRTY (оцінка%)`, `UNCHECKED` для ще не перевірених записів або
  `INVALID`.
- **`--edit-ips`** відкриває тимчасову копію. Під час збереження показує
  некоректні записи й пропонує відредагувати знову, зберегти попри це або
  скасувати. Некоректні записи, які вже були у файлі, лише згадуються. Без
  терміналу нові некоректні записи ніколи не зберігаються.

Файл, як і раніше, можна редагувати вручну:

```bash
sudo editor /etc/abuse-checker/ips.txt
```

```
# один запис на рядок, коментарі через '#'
203.0.113.10
203.0.113.11          # поштовий релей
198.51.100.0/28       # діапазон офісу
2001:db8::1
```

Некоректні рядки пропускаються із попередженням у лозі. Дублікати
ігноруються. Якщо видалити запис, його стан буде прибрано під час наступного
запуску. Якщо додати новий, він отримає статус `NEW`, щойно вперше стане
брудним. Нічого перезапускати не потрібно: наступний запуск підхопить зміни.

### Отримувачі

Усі ці налаштування приймають списки через кому. Відредагуйте зашифроване
сховище, а потім перевірте доставку:

```bash
sudo abuse-checker --edit-secrets
sudo abuse-checker --test-notify
```

Порожнє налаштування просто вимикає відповідний конектор. Щоб прибрати
команду, видаліть її зі списку. Щоб додати новий тип каналу, див.
[Конектори](#конектори).

- **Telegram:** створіть бота через @BotFather і додайте його в кожну групу.
  Щоб дізнатися ідентифікатори чатів, напишіть боту повідомлення і відкрийте
  в браузері `https://api.telegram.org/bot<TOKEN>/getUpdates` (ніколи не
  вставляйте токен в історію оболонки на спільному сервері). Кожен чат
  отримує HTML-підсумок (`sendMessage`) і звіт як файл (`sendDocument`).
- **Slack:** створіть окремий *Incoming Webhook* для кожного каналу чи
  робочого простору і додайте всі URL до `SLACK_WEBHOOK_URLS`. Повідомлення
  використовують Block Kit і містять кнопку для кожної IP-адреси.
- **Email:** один лист надсилається всім отримувачам: текстовий підсумок у
  тілі листа і HTML-звіт у вкладенні.
- **Jira:** див. розділ [Jira](#jira) нижче.

### Jira

Коли спрацьовує сповіщення (є хоча б одна IP-адреса зі статусом `NEW` або
`ESCALATED`, або використано `--force-full-report`), `40-jira.sh` робить таке:

1. Шукає найновішу **відкриту** задачу в `JIRA_PROJECT_KEY` з мітками
   `abuse-checker` і `abuse-checker-<хост>`. Для цього використовує
   `/rest/api/3/search/jql` у Jira Cloud і переходить на `/rest/api/2/search`
   у Server/Data Center.
2. Якщо така задача є, **додає до неї коментар**. Якщо немає, **створює**
   задачу, де заголовок сповіщення стає назвою задачі, з типом
   `JIRA_ISSUE_TYPE`, мітками та необов'язковим `JIRA_PRIORITY`. Щоб щоразу
   створювати нову задачу, встановіть `JIRA_UPDATE_MODE="create"`.
3. Опис або коментар — це таблиця у wiki-розмітці Jira з такими стовпцями:
   статус, IP/підмережа, оцінка, скарги з `+delta`, ISP, країна, час останньої
   скарги та посилання на сторінку перевірки AbuseIPDB.
4. Прикріплює `report_YYYY-MM-DD.html` до задачі (щоб вимкнути це,
   встановіть `JIRA_ATTACH_REPORT="false"`).

Коли задачу вирішено і її статус належить до категорії Done, наступне
сповіщення створить нову задачу. У Jira Cloud задайте `JIRA_USER_EMAIL` і
[API-токен](https://id.atlassian.com/manage-profile/security/api-tokens);
конектор надсилає їх як HTTP Basic auth. У Server/Data Center залиште
`JIRA_USER_EMAIL` порожнім і вкажіть персональний токен доступу в
`JIRA_API_TOKEN`; він надсилається як Bearer-токен. В обох випадках токен і
похідний заголовок `Authorization` потрапляють у curl лише через
`--config -` (stdin), а сам токен маскується в логах.

```bash
sudo abuse-checker --edit-secrets   # JIRA_BASE_URL, JIRA_USER_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY, ...
sudo abuse-checker --test-notify    # створює задачу "[TEST] ..."
```

---

## Зашифровані секрети

Секрети зберігаються в зашифрованому вигляді. Рівень визначається
автоматично під час першого збереження секретів:

| Рівень | Коли | Файли | Як їх отримує сервіс |
|--------|------|-------|----------------------|
| 1. `systemd-creds` | працює systemd ≥ 250 і `systemd-creds encrypt` спрацьовує (TPM2 та/або ключ хоста) | `secrets.cred` | `LoadCredentialEncrypted=secrets:...`. systemd розшифровує у приватний каталог облікових даних сервісу, який не потрапляє у swap. |
| 2. OpenSSL | у всіх інших випадках | `secrets.conf.enc` + `.master.key` | `LoadCredential=master.key:...`. Сервіс розшифровує через `openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000` у пам'ять (канал) і підключає результат. |
| Застарілий | звичайний `secrets.conf`, який ви створили самі | `secrets.conf` | `EnvironmentFile=`. Досі працює, але під час кожного запуску пише попередження. |

Відповідний drop-in systemd, `abuse-checker.service.d/10-secrets.conf`,
перезаписується автоматично щоразу, коли змінюється сховище. Рівень можна
задати примусово через `ABUSE_CHECKER_CRYPTO=openssl|systemd`.

```bash
sudo abuse-checker --edit-secrets      # розшифрувати -> /dev/shm (0600) -> $EDITOR -> перевірити -> зашифрувати -> знищити
sudo abuse-checker --encrypt-secrets   # перенести звичайний secrets.conf і знищити його
printf '%s\n' "$VALUE" | sudo abuse-checker --set-secret SLACK_WEBHOOK_URLS   # для скриптів, значення через stdin
```

Як працює `--edit-secrets`:

- Розшифрована копія існує лише як файл із правами `0600` у `/dev/shm`, тобто
  в оперативній пам'яті. Якщо `/dev/shm` недоступний, команда відмовляється
  працювати, а не записує файл на диск.
- Редактор вибирається в такому порядку: `$VISUAL`, `$EDITOR`, `nano`, `vi`.
- Після виходу з редактора файл перевіряється: дозволені лише коментарі та
  рядки `KEY="value"`, і `bash -n` має пройти успішно. Якщо перевірка не
  пройшла, редактор можна відкрити знову. Якщо ви відмовитеся, нічого не
  зміниться.
- Новий шифротекст перевіряється повторним розшифруванням, перш ніж він
  замінить старий файл. Після цього копія в RAM знищується, зокрема при
  помилках і Ctrl-C.
- Якщо ви зберегли файл без змін, повторне шифрування не виконується.

Зберігайте резервну копію `.master.key` (або ключа облікових даних systemd на
хості) разом із `secrets.conf.enc`. Без ключа секрети відновити неможливо, і
запуск переривається з помилкою `cannot decrypt`, а не працює з порожньою
конфігурацією.

---

## Конектори

Сповіщення надсилають модулі з `/usr/local/lib/abuse-checker/connectors.d/`
(або з `connectors/` під час запуску з робочої копії репозиторію). Кожен файл
`*.sh` виконується в порядку імен, кожен **у власній підоболонці**, тож збій
одного конектора не зупиняє інші та сам запуск.

| Файл | Налаштування |
|------|--------------|
| `10-telegram.sh` | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_IDS` |
| `20-slack.sh` | `SLACK_WEBHOOK_URLS` |
| `30-email.sh` | `EMAIL_TO`, `EMAIL_FROM`, `SMTP_URL`, `SMTP_USER`, `SMTP_PASS` |
| `40-jira.sh` | `JIRA_BASE_URL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY` (обов'язкові), а також `JIRA_USER_EMAIL`, `JIRA_ISSUE_TYPE`, `JIRA_UPDATE_MODE`, `JIRA_LABELS`, `JIRA_PRIORITY`, `JIRA_ATTACH_REPORT` |
| `99-custom.sh.example` | Задокументований шаблон. Не завантажується, бо не закінчується на `.sh`. |

Конектор визначає дві функції:

```bash
connector_enabled   # повертає 0, коли налаштування задані; інакше конектор мовчки пропускається
connector_send      # $1 = класифікований JSON, $2 = report.html, $3 = заголовок; ненульовий код = збій (пишеться в лог)
```

Файли, які могли б зламати запуск, пропускаються з попередженням, а решта
конекторів усе одно виконується. Файл пропускається, якщо він:

1. порожній (0 байтів) або містить лише пробіли й коментарі;
2. не проходить `bash -n`;
3. не визначає обидві функції `connector_enabled` і `connector_send` після
   підключення в тестовій підоболонці.

Щоб додати конектор, виконайте
`sudo install -m 0644 99-custom.sh.example /usr/local/lib/abuse-checker/connectors.d/40-mywebhook.sh`.
Відредагуйте його, додайте його налаштування через `--edit-secrets` і
перевірте через `abuse-checker --status` (рядок `Connectors`) та
`--test-notify`. Конектори можуть використовувати вбудовані допоміжні функції
`secure_curl`, `cfg_line`, `split_csv`, `plain_summary`, `info` і `warn`.
Будь-яке налаштування, назва якого містить `TOKEN`, `_KEY`, `PASS`, `SECRET`
чи `WEBHOOK`, автоматично маскується в логах. Інсталятор оновлює вбудовані
конектори і не чіпає ваші власні.

---

## Довідка CLI

```
abuse-checker [--run | --dry-run | --test-notify | --force-full-report | --status | --reset-state]
abuse-checker [--edit-secrets | --encrypt-secrets | --set-secret KEY | --uninstall [--keep|--purge]]
abuse-checker [--check-update | --update [--force]]
abuse-checker [--list-ips | --add-ip IP... [--comment T] | --del-ip IP... | --edit-ips]
abuse-checker [--schedule SPEC|show|reset | --watchdog-recover]
```

| Прапорець             | Дія |
|-----------------------|-----|
| `--run`               | Типовий режим. Запускає перевірку, оновлює стан, сповіщає про `NEW`/`ESCALATED`. |
| `--dry-run`           | Використовує вбудовані тестові відповіді API та окремий `state.dryrun.json`. Створює `report_<дата>_dryrun.html`. Не надсилає сповіщень і не звертається до мережі. Якщо `ips.txt` недоступний для читання, бере зразкові адреси. |
| `--test-notify`       | Створює зразковий звіт (`report_<дата>_test.html`) і надсилає його в усі налаштовані канали. Стан не змінюється. |
| `--force-full-report` | Звичайний запуск, але сповіщає про **всі** брудні IP-адреси, включно з `UNCHANGED`. |
| `--status`            | Показує кількість відстежуваних IP, брудних/чистих, час останнього запуску, кількість звітів, кількість ключів, сховище секретів, активні конектори і наступний запуск таймера. |
| `--reset-state`       | Очищає `state.json` (і стан dry-run). Наступний запуск вважатиме всі брудні IP-адреси `NEW`. |
| `--edit-secrets`      | Лише root. Розшифрувати в RAM, відредагувати, перевірити, зашифрувати, знищити копію. Див. [Зашифровані секрети](#зашифровані-секрети). |
| `--encrypt-secrets`   | Лише root. Перенести звичайний `secrets.conf` у зашифроване сховище і знищити оригінал. |
| `--set-secret KEY`    | Лише root. Задати одну змінну, значення читається зі stdin (воно ніколи не з'являється в `ps`). |
| `--list-ips`, `--ips` | Нумерований список `ips.txt` з коментарями та станом (`CLEAN`, `DIRTY (оцінка%)`, `UNCHECKED`, `INVALID`). |
| `--add-ip IP\|CIDR ... [--comment ТЕКСТ]` | Лише root. Перевірити й додати записи; дублікати пропускаються, і нічого не додається, якщо хоча б одне значення некоректне. |
| `--del-ip`, `--rm-ip IP\|CIDR ...` | Лише root. Видалити записи з `ips.txt` і зі `state.json`. |
| `--edit-ips`          | Лише root. Редагувати `ips.txt` у `$EDITOR` з перевіркою під час збереження. |
| `--schedule SPEC`     | Лише root. Задати час запусків (`"06:00,18:00"`, `every 6h`, `hourly`, вираз OnCalendar) або `show` / `reset`. Див. [Розклад](#розклад). |
| `--watchdog-recover`  | Лише root. Відновити юніт у стані failed, застаріле блокування чи неактивний таймер і надіслати сповіщення. Див. [Watchdog](#watchdog-і-автовідновлення). |
| `--check-update`      | Порівняти встановлену версію з останньою на GitHub. |
| `--update`, `--self-update` | Лише root. Завантажити, перевірити (`bash -n`) і встановити останню версію (`--force` перевстановлює). Див. [Оновлення](#оновлення). |
| `--uninstall`         | Лише root. Інтерактивне меню або `--keep` / `--purge` для скриптів. Див. [Видалення](#видалення). |
| `--help`, `--version` | Показує довідку або версію. |

Під час ручного запуску використовуйте `sudo abuse-checker ...`, щоб скрипт
міг розшифрувати секрети. Або дозвольте systemd запустити його від імені
сервісного користувача: `sudo systemctl start abuse-checker.service`.

---

## Щоденне обслуговування

```bash
abuse-checker --status                         # підсумок + наступний запуск (від root)
systemctl list-timers abuse-checker.timer      # коли наступний запуск
journalctl -u abuse-checker --since today      # логи сьогоднішнього запуску
sudo systemctl start abuse-checker.service     # запустити зараз, як це зробить сервіс
sudo ls -lt /var/lib/abuse-checker/reports/    # останні звіти
sudo abuse-checker --force-full-report         # повторно надіслати повну картину
```

Щоб змінити час запусків, див. [Розклад](#розклад).

---

## Розклад

Типово перевірка запускається раз на день о 06:00 з випадковою затримкою до
15 хвилин. Щоб змінити це без редагування юнітів:

```bash
sudo abuse-checker --schedule "06:00,14:00,22:00"   # кілька фіксованих часів
sudo abuse-checker --schedule "every 6h"            # також: 6h, 12h, hourly, daily, 2x/day
sudo abuse-checker --schedule "Mon..Fri *-*-* 09:15:00"   # будь-який вираз OnCalendar systemd
sudo abuse-checker --schedule show                  # поточний розклад і наступні запуски
sudo abuse-checker --schedule reset                 # повернути щоденний запуск о 06:00
```

| Специфікація | Що записується в OnCalendar |
|--------------|-----------------------------|
| `06:00,18:00` | `*-*-* 06:00:00`, `*-*-* 18:00:00` |
| `hourly` / `1h` | `hourly` |
| `6h`, `every 6h` (також `2h 3h 4h 8h 12h`) | `*-*-* 00/6:00:00` |
| `daily` | `*-*-* 06:00:00` |
| `2x/day` / `4x/day` | 06:00 + 18:00 / кожні 6 год |
| будь-що інше | використовується як є |

Кожен вираз перевіряється через `systemd-analyze calendar` ще до запису, і
некоректне введення нічого не змінює. Розклад записується в
`/etc/systemd/system/abuse-checker.timer.d/override.conf`, який починається з
порожнього `OnCalendar=`, щоб скинути типове значення. Потім команда виконує
`systemctl daemon-reload && systemctl restart abuse-checker.timer` і показує
найближчі запуски. Майстер налаштування ставить те саме запитання: раз на
день (типово), 2 рази на день, 4 рази на день або власний час. Оновлення
ніколи не перезаписують ваш override.

---

## Watchdog і автовідновлення

`abuse-checker.service` відновлюється самостійно:

| Налаштування | Дія |
|--------------|-----|
| `TimeoutStartSec=15min`, `RuntimeMaxSec=15min` | Запуск, що завис на 15 хвилин, примусово завершується. Запуск `Type=oneshot` вважається таким, що стартує, доки не завершиться, тож фактично діє ліміт `TimeoutStartSec`. |
| `Restart=on-failure`, `RestartSec=60s` | Запуск, що впав або був примусово завершений, повторюється через 60 с. |
| `StartLimitIntervalSec=15min`, `StartLimitBurst=3` | Не більше 3 запусків за 15 хвилин. Після цього юніт позначається як failed... |
| `OnFailure=abuse-checker-watchdog.service` | ...і запускається watchdog. |

`abuse-checker-watchdog.service` виконує `abuse-checker --watchdog-recover`
від root. Його запускає `OnFailure=`, а також кожні 6 годин
`abuse-checker-watchdog.timer`. Він:

1. скидає стан failed для `abuse-checker.service`;
2. видаляє `/var/lib/abuse-checker/.lock`, якщо жоден процес його не тримає
   (утримуване блокування означає, що запуск триває, тож його не чіпають);
3. перевіряє, що `abuse-checker.timer` увімкнено й активно, і перезапускає
   його, якщо ні;
4. перевіряє, що останній успішний запуск був не давніше ніж
   `WATCHDOG_MAX_AGE_HOURS` годин тому (типово 48);
5. якщо щось було не так, надсилає в усі налаштовані конектори сповіщення з
   високим пріоритетом
   **`[WATCHDOG ALERT] abuse-checker on <хост> crashed and was recovered`**.
   Сповіщення містить список проблем, виконані дії з відновлення та останні
   15 рядків `journalctl -u abuse-checker.service` з замаскованими
   секретами.

Як кожен конектор надсилає сповіщення watchdog:

- **Telegram:** повідомлення 🚨 з логом у блоці `<pre>`.
- **Slack:** заголовок `:rotating_light:` з логом у блоці коду.
- **Email:** лист із заголовками `X-Priority: 1` і `Importance: high`.
- **Jira:** завжди **нова** задача з міткою `abuse-checker-watchdog` і
  пріоритетом `JIRA_WATCHDOG_PRIORITY`, якщо його задано.

Справна система сповіщень не надсилає.

```bash
sudo abuse-checker --watchdog-recover           # запустити перевірку вручну
systemctl list-timers abuse-checker-watchdog.timer
journalctl -u abuse-checker-watchdog -n 30
```

---

## Оновлення

Основний репозиторій —
[`egwyl666/abuseDB-checker`](https://github.com/egwyl666/abuseDB-checker),
гілка `main`.

```bash
sudo abuse-checker --check-update    # порівняти встановлену версію з останньою на GitHub
sudo abuse-checker --update          # те саме, що --self-update; --force перевстановлює
```

`--update` працює так:

1. Завантажує архів гілки в приватний тимчасовий каталог.
2. Виконує `bash -n` для завантажених `abuse-checker.sh`, `install.sh` і
   кожного конектора та зчитує новий `AC_VERSION`. Якщо будь-яка перевірка
   не пройшла, зупиняється **ще до будь-яких змін у системі**, і встановлена
   версія продовжує працювати.
3. Запускає новий `install.sh --no-wizard`. Він атомарно замінює виконуваний
   файл і оновлює конектори та юніти systemd. Ваші секрети, `ips.txt`,
   `state.json`, звіти й власні конектори зберігаються.

Встановлення однією командою робить те саме, і його можна безпечно
повторювати. Із робочої копії репозиторію також можна виконати
`git pull && sudo ./install.sh`.

### Автоматичні оновлення (`AUTO_UPDATE`)

Задається через `sudo abuse-checker --edit-secrets` або в майстрі
налаштування.

| Значення | Поведінка |
|----------|-----------|
| `notify` (типово) | Раз на день під час запланованого запуску перевіряє GitHub; результат кешується в `/var/lib/abuse-checker/update-check.json`. Якщо є новіша версія, записує це в лог і додає `Update available: vX.Y.Z -> Run 'sudo abuse-checker --update'` до HTML-звіту, нижньої частини повідомлень Telegram і Slack та тексту листа. |
| `true` | Перед щоденною перевіркою `ExecStartPre=-+/usr/local/bin/abuse-checker --auto-update` запускається від root поза пісочницею і встановлює новішу версію з тими самими перевірками, що й `--update`. Невдале чи відхилене оновлення записується в лог і ніколи не блокує перевірку. |
| `false` | Заплановані запуски ніколи не звертаються до GitHub. |

`REPO_SLUG` і `REPO_BRANCH` дозволяють вказати форк або іншу гілку.
`abuse-checker --status` показує поточну політику та останню знайдену версію.

Якщо ви оновлюєтеся з версії 1.0 зі звичайним `secrets.conf`, завершіть
оновлення командою `sudo abuse-checker --encrypt-secrets`. Щоб знайти нові
параметри, порівняйте `/etc/abuse-checker/secrets.conf.example` із вмістом
`sudo abuse-checker --edit-secrets`.

---

## Видалення

```bash
sudo abuse-checker --uninstall           # інтерактивне меню
sudo abuse-checker --uninstall --keep    # для скриптів: те саме, що варіант [1]
sudo abuse-checker --uninstall --purge   # для скриптів: те саме, що варіант [2]
sudo ./uninstall.sh [--keep|--purge]     # те саме з робочої копії репозиторію
```

Інтерактивне меню показує кожен шлях, який буде видалено, і його розмір:

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

[1] — видаляє лише застосунок і таймер systemd, а зашифровані секрети,
`ips.txt` і HTML-звіти зберігаються. [2] — повне очищення, включно з
`/etc/abuse-checker`, `/var/lib/abuse-checker` і користувачем
`abusechecker`. [3] — скасувати (типовий варіант). Повне очищення треба
підтвердити, ввівши `purge`; перед видаленням каталогів воно знищує майстер-ключ
і всі незашифровані секрети. Без TTY команда не вгадує: передайте `--keep` або
`--purge`.

---

## Модель безпеки

- **Шифрування на диску.** Секрети зберігаються через `systemd-creds` або
  AES-256 (OpenSSL, PBKDF2 зі 100 000 ітерацій, випадковий 256-бітний ключ).
  Відкритий текст існує лише в каналах, у пам'яті процесу або, під час
  редагування, у файлі з правами `0600` у `/dev/shm`, який потім знищується.
  Ключ передається в openssl як `-pass file:` і ніколи не потрапляє в
  командний рядок. Див. [Зашифровані секрети](#зашифровані-секрети).
- **Жодних секретів у списку процесів.** Кожен виклик `curl` отримує URL і
  заголовки через `curl --config -` зі stdin. API-ключі, токен Telegram (який
  є частиною URL), URL вебхуків Slack та облікові дані SMTP ніколи не
  потрапляють в `argv`, тож `ps aux` і `/proc/<pid>/cmdline` їх не покажуть.
  Набір тестів це перевіряє.
- **Маскування в логах.** Увесь stdout і stderr, включно з власними
  повідомленнями про помилки `curl`, проходить через фільтр `awk`, який
  виконує буквальний (не regex) пошук і замінює кожен налаштований секрет на
  `***REDACTED***`, перш ніж текст потрапить у термінал чи journald. Фільтр
  отримує секрети через своє середовище, а не через аргументи.
- **Пісочниця systemd.** Сервіс працює від окремого користувача
  `abusechecker` з оболонкою `nologin`. Використовуються `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp` і `PrivateDevices`,
  порожній набір capabilities, захист ядра/cgroup та обмежені сімейства
  адрес. Єдиний доступний для запису шлях —
  `ReadWritePaths=/var/lib/abuse-checker`.
- **Права доступу до файлів.** `.master.key` має права `0400 root:root`, а
  `secrets.cred` — `0600 root:root`. systemd читає обидва файли від root і
  передає їх сервісу через його приватний каталог облікових даних.
  Застарілий звичайний `secrets.conf` має бути `0600`, і скрипт
  відмовляється підключати його, якщо файл доступний для запису всім. Стан і
  звіти мають права `0640` і `0750` відповідно.
- **Перевірені оновлення.** Оновлення надходять лише з налаштованого
  репозиторію GitHub через HTTPS. Вони розпаковуються в приватний тимчасовий
  каталог і проходять перевірку синтаксису ще до встановлення. Єдиний крок,
  що виконується від root поза пісочницею, — попередній крок для
  `AUTO_UPDATE=true` (префікс `+`). Він нічого не робить, якщо цей режим
  вимкнено. Використовуйте `notify`, якщо хочете самі переглядати зміни.
- **Ізольовані конектори.** Кожен конектор виконується у власній
  підоболонці після перевірки синтаксису та інтерфейсу.
- **Безпека HTML.** Кожне значення з API екранується (`@html`) перед
  вставленням у звіт, а сам звіт не завантажує зовнішніх скриптів чи стилів.
- Одночасно працює лише один екземпляр (`flock` на
  `/var/lib/abuse-checker/.lock`).

---

## Тестування

```bash
bash tests/run_tests.sh          # KEEP_WORK=1 зберігає тимчасовий каталог для аналізу
```

Тести працюють повністю офлайн. Вони підміняють `curl` на
`tests/mock_curl.sh` через змінну `ABUSE_CHECKER_CURL` і спрямовують каталоги
налаштувань і стану в тимчасовий каталог (`ABUSE_CHECKER_CONF_DIR`,
`ABUSE_CHECKER_STATE_DIR`, `ABUSE_CHECKER_CONNECTORS_DIR`,
`ABUSE_CHECKER_RAMDIR`, `ABUSE_CHECKER_DROPIN_DIR`). Покриття:

- `bash -n` і `shellcheck` для кожного скрипта;
- тестові відповіді для чистої IP, щойно забрудненої IP, IP з ескалацією,
  незмінної брудної IP та CIDR-блоку, а також перемикання ключів при HTTP 429
  і вичерпання всіх ключів;
- переходи стану `NEW` → `UNCHANGED` → `ESCALATED` (більша кількість скарг і
  новіший `lastReportedAt`), а також брудна → чиста → `NEW`;
- відсутність звіту й сповіщень, коли нічого не змінилося, та
  `--force-full-report`;
- коректність HTML (doctype, збалансовані рядки, розмір менше 30 КБ,
  екранування, значки delta, посилання, відсутність зовнішніх ресурсів);
- секрети: ніколи не потрапляють в argv curl, завжди передаються через stdin,
  маскуються в логах (включно з імітованими помилками curl) і відсутні в
  стані та звітах;
- розгортання CIDR, `--dry-run`, `--test-notify`, `--status`, `--reset-state`
  та видалення старих звітів;
- конектори: завантаження з `connectors.d`; файл на 0 байтів, файл лише з
  пробілами чи коментарями, синтаксична помилка, відсутній інтерфейс,
  конектор зі збоєм і вимкнений конектор дають попередження або мовчки
  пропускаються, а інші конектори все одно доставляють сповіщення; власний
  конектор, створений із шаблону; `ips.txt` лише з коментарями та порожні
  налаштування конекторів;
- шифрування: перенесення через `--encrypt-secrets` (заголовок salt,
  майстер-ключ із 64 шістнадцяткових символів, права `0400`/`0640`,
  перевірка повного циклу шифрування й розшифрування, drop-in); запуск із
  зашифрованого сховища; завантаження через `CREDENTIALS_DIRECTORY`;
  `--set-secret` через stdin; `--edit-secrets` (файл у RAM має права `0600`,
  зміни шифруються повторно, некоректні правки відхиляються, редагування без
  змін нічого не робить, файл у RAM знищується); неправильний майстер-ключ
  перериває запуск; openssl ніколи не отримує секретів в argv; у каталогах
  налаштувань, стану, RAM і tmp не лишається відкритих секретів; а також рівень
  `systemd-creds`, якщо він доступний;
- Jira: задача створюється з правильним вмістом запиту (проєкт, тип задачі,
  пріоритет, мітки разом із міткою хоста, назва, wiki-таблиця з `+delta` і
  посиланнями на AbuseIPDB, текст ISP), і звіт прикріплюється; до відкритої
  задачі додається коментар замість дубліката; перехід на
  `/rest/api/2/search` і Bearer PAT для Server/DC; `JIRA_UPDATE_MODE=create`;
  помилка API Jira показується, а інші конектори все одно надсилають
  сповіщення; Jira пропускається, якщо не налаштована; `--test-notify` до неї
  доходить; токен і заголовок Basic ніколи не потрапляють в argv, а токен
  маскується в логах;
- Jira з `JIRA_BASE_URL`/`JIRA_USER_EMAIL`: `POST /rest/api/2/issue` з
  проєктом, типом задачі й підсумковою таблицею; HTML-звіт завантажується в
  `/attachments` із `X-Atlassian-Token: no-check`; Basic auth; токен ніколи
  не потрапляє в argv і маскується у виводі;
- список IP: `--add-ip` з IPv4, IPv6 (скорочені форми, вбудований IPv4) і
  CIDR, вбудовані коментарі, збереження прав `0644`, виявлення дублікатів
  (IPv6 без урахування регістру), відхилення за принципом «все або нічого»
  для `999.1.1.1`, `/33`, `:::`, `hello` і `/129`; стани, коментарі та
  нумерація в `--list-ips`; `--del-ip` і `--rm-ip` видаляють записи з
  `ips.txt` і `state.json` та повідомляють `not found`; `--edit-ips`
  зберігає коректні зміни, без TTY не зберігає нових некоректних записів і
  прибирає тимчасовий файл;
- `--schedule`: вміст drop-in для `"06:00,18:00"`, `"7:05, 22:30"`,
  `every 6h`, `6h`, `every 12h`, `hourly`, `daily` і `2x/day`; відхилення
  `7h`, `25:00` і некоректних довільних виразів (через `systemd-analyze`);
  довільний OnCalendar; `daemon-reload` і перезапуск таймера; `show` і
  `reset`;
- watchdog: справна система не надсилає сповіщень; юніт у стані failed,
  застаріле блокування та неактивний чи вимкнений таймер відновлюються, а
  сповіщення надходить у Telegram, Slack, email (високий пріоритет) і Jira
  (нова задача з міткою й пріоритетом watchdog); 15 рядків журналу
  включаються з замаскованими секретами; утримуване блокування не
  чіпається; застарілий `lastRun` викликає сповіщення; налаштування юнітів
  перевіряються, і юніти проходять `systemd-analyze verify`;
- самооновлення: `--check-update` (новіша версія, та сама, GitHub
  недоступний); `--update` зі справним релізом, пошкодженим
  `abuse-checker.sh`, пошкодженим конектором, архівом-сміттям і невдалим
  завантаженням (кожен відхиляється, а встановлений файл лишається
  побайтово незмінним); та сама версія і `--force`; `AUTO_UPDATE=notify`
  (банер у звіті, Telegram, Slack і листі, одна перевірка на день), `false`
  (жодного запиту до GitHub) і `true` (`--auto-update` встановлює, а
  пошкоджене оновлення ніколи не ламає сервіс); початкове завантаження
  через `install.sh` з каналу (завантаження, перевірка, відхилення,
  прибирання);
- `--uninstall` у фіктивному корені: текст меню та шляхи, скасування, `[1]`,
  `[2]` з введеним підтвердженням і без нього, відмова без TTY, а також
  обгортка `uninstall.sh`.

---

## Усунення несправностей

| Симптом | Рішення |
|---------|---------|
| `ABUSEIPDB_API_KEYS is not configured` | Додайте ключ через `sudo abuse-checker --edit-secrets`. Ручні перевірки запускайте через `sudo`. |
| `secrets are encrypted but the master key is not readable` | Запускайте через `sudo` або через systemd (`systemctl start abuse-checker`). |
| `cannot decrypt ... (wrong or missing master key?)` | `.master.key` не відповідає `secrets.conf.enc`. Відновіть обидва файли з резервної копії або видаліть `.enc` і введіть секрети знову через `--edit-secrets`. |
| `secrets are stored in plain text` | Виконайте `sudo abuse-checker --encrypt-secrets`. |
| `RAM directory /dev/shm not available` | Змонтуйте tmpfs у `/dev/shm` або вкажіть інший каталог tmpfs у `ABUSE_CHECKER_RAMDIR`. |
| `connector X: ... skipped` | Цей файл у `connectors.d` порожній, містить синтаксичну помилку або не має `connector_enabled`/`connector_send`. Виправте або видаліть його. |
| `Jira issue creation failed (HTTP 400): ...` | Показується власна помилка Jira, часто неправильний `JIRA_ISSUE_TYPE` або обов'язкове поле, наприклад компонент. Виправте через `--edit-secrets` і повторіть із `--test-notify`. |
| `Jira ... (HTTP 401/403)` | Неправильний `JIRA_USER_EMAIL` чи токен, або обліковий запис не може створювати задачі в проєкті. У Server/DC залиште `JIRA_USER_EMAIL` порожнім, щоб використати PAT. |
| `error: invalid IP/CIDR: ...` від `--add-ip` | Нічого не додано. Виправте або приберіть вказане значення, наприклад `/33` чи `999.x`, і повторіть команду. |
| `invalid OnCalendar expression` | Перевірте вираз через `systemd-analyze calendar '<вираз>'` або використайте одну з готових специфікацій. |
| Надійшло `[WATCHDOG ALERT]` | Сервіс тричі впав за 15 хвилин або завис. Перегляньте рядки логу в сповіщенні та `journalctl -u abuse-checker -n 100`. Відновлення вже виконано, і наступний запуск за таймером спробує знову. |
| `start request repeated too quickly` | Досягнуто ліміту запусків (3 за 15 хвилин). Watchdog скидає його; також можна виконати `sudo systemctl reset-failed abuse-checker`. |
| `no connector delivered the alert` | Жоден конектор не налаштовано. Перевірте рядок `Connectors` у `--status`, потім виконайте `--edit-secrets`. |
| `IP list not readable` | Перевірте, що `ips.txt` існує і має права `0644 root:abusechecker`. Повторний запуск `install.sh` виправить права. |
| `state directory ... does not exist` | Виконайте `sudo ./install.sh`. |
| `another abuse-checker instance is running` | Триває інший запуск або блокування утримує запущений процес. Перевірте `systemctl status abuse-checker`. |
| `API key #N rate-limited (HTTP 429)` | Денну квоту вичерпано. Додайте ключі, встановіть `REQUEST_DELAY` або використовуйте `check-block` для діапазонів. |
| `API key #N rejected (HTTP 401/403)` | Ключ недійсний або відкликаний. |
| Лише рядки `ERROR` | Перевірте вихідний HTTPS (`curl -sI https://api.abuseipdb.com`), DNS і `RestrictAddressFamilies` сервісу. |
| Telegram `sendMessage ... failed` | Бота немає в групі, його ніколи не запускали в особистому чаті, або неправильний ідентифікатор чату. Для груп потрібен ідентифікатор `-100...`. |
| Slack `webhook #N failed` | Вебхук відкликано або канал заархівовано. Створіть вебхук заново. |
| Пошта не доставляється | Перевірте `SMTP_URL`, порт і облікові дані. Для Gmail використовуйте пароль застосунку. Без `SMTP_URL` потрібен робочий локальний `sendmail`. |
| Сповіщень немає взагалі | Це нормально, поки нічого не змінюється. Перевірте через `--force-full-report` або `--test-notify`. |
| Забагато сповіщень `NEW` після скидання | Очікувано: `--reset-state` стирає історію. |
| `update check failed: HTTP ...` | GitHub недоступний або `REPO_SLUG`/`REPO_BRANCH` неправильні. Перевірка повториться наступного дня, більше ні на що це не впливає. |
| `... fails 'bash -n'; update rejected` | Гілка в репозиторії зламана. Встановлена версія продовжує працювати. Спробуйте пізніше або зафіксуйте `REPO_BRANCH`. |
| `curl ... install.sh \| sudo bash` повертає 404 | Гілки `main` (ще) немає. Використайте `sudo AC_BRANCH=<гілка> bash`. |
| `--edit-secrets` повідомляє `invalid line(s)` | Використовуйте `KEY="value"` або `KEY='value'` без `$(...)`, зворотних лапок і `;`. |
| Пошкоджений `state.json` | Скрипт запише попередження в лог і автоматично почне з чистого стану. Також можна виконати `--reset-state`. |

Налагодження запуску в інтерактивному режимі із середовищем сервісу:

```bash
sudo systemd-run --pty --wait -p User=abusechecker \
  -p LoadCredential=master.key:/etc/abuse-checker/.master.key \
  -p ReadWritePaths=/var/lib/abuse-checker /usr/local/bin/abuse-checker --run
```
