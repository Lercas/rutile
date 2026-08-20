<p align="center">
  <img src="assets/banner.svg" alt="rutile — секреты, которыми агент может пользоваться, но не может слить" width="880">
</p>

<p align="center">
  <img alt="version" src="https://img.shields.io/badge/version-1.4.0-E8B84B?style=flat-square&labelColor=1A1713">
  <img alt="go" src="https://img.shields.io/badge/go-1.25-E8B84B?style=flat-square&labelColor=1A1713&logo=go&logoColor=EDE8DF">
  <img alt="platform" src="https://img.shields.io/badge/platform-macOS%20·%20Linux-9B937F?style=flat-square&labelColor=1A1713">
  <img alt="mcp" src="https://img.shields.io/badge/MCP-native-E8B84B?style=flat-square&labelColor=1A1713">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-9B937F?style=flat-square&labelColor=1A1713">
</p>

<p align="center">
  <a href="README.md">English</a> · <b>Русский</b> · <a href="AGENTS.md">AGENTS.md</a> · <a href="SECURITY.md">SECURITY.md</a> · <a href="CHANGELOG.md">CHANGELOG</a>
</p>

Локальный secrets-брокер для людей **и мультиагентных AI-систем** — идейный
наследник `pass`/`passage`, перестроенный для мира, где в терминале живут
агенты. Всё, что агент *видел*, может утечь через prompt injection; каждый
статический ключ в MCP-конфиге — утечка, которая ещё не случилась. rutile
даёт каждому агенту собственную идентичность, default-deny политику,
ограниченные гранты, audit trail — и способы пользоваться секретами, вообще
не помещая их в контекст LLM.


## Быстрый старт (человек)

```bash
make install          # или: go install ./cmd/rutile

rutile init                        # один раз: придумать passphrase
rutile add dev/myproject/api-key   # сохранить секрет
rutile show dev/myproject/api-key  # прочитать
rutile ls                          # список
rutile generate dev/db/password    # сгенерировать пароль
```

Демон стартует сам при первой команде. Если хранилище закрыто, любая команда
сама спросит passphrase; после 30 минут простоя ключ выгружается из памяти
(auto-lock). Принудительно: `rutile lock`.

Переезжаете? Замена текущего менеджера — одна команда:

```bash
rutile import passage              # из passage (age)
rutile import pass                 # из pass (gpg)
rutile import env .env --prefix dev/myproject
```

## Подключение AI-агента (Claude Code или любой MCP-клиент)

```bash
rutile agent add claude
# напечатает токен (один раз!) и готовую строку вида:
#   claude mcp add claude -e RUTILE_AGENT=claude -e RUTILE_TOKEN=rtl_... -- rutile mcp

rutile allow claude "dev/**"                 # что агенту можно читать
rutile allow claude "prod/db" --for 1h       # временный доступ
rutile allow claude "deploy/key" --one-time  # сгорает после первого чтения
```

MCP-инструменты агента (полный контракт — в [AGENTS.md](AGENTS.md)):

| Инструмент | Назначение |
|---|---|
| `get_secret` | читает секрет; необязательный `reason` попадает в ваш аудит |
| `list_secrets` | только те пути, которые агенту разрешены |
| `request_access` | запрос доступа к закрытому пути с обоснованием |
| `delegate_access` | scoped суб-токен для агента-помощника |
| `store_status` | открыто ли хранилище, сколько секретов видно |

Всё, что не разрешено явно, — запрещено. Агенты работают **только на
чтение** — записывает и удаляет только человек.

```bash
rutile policy                 # все правила
rutile deny claude "dev/**"   # убрать правило
rutile agent revoke claude    # отозвать агента целиком
```

### Human-in-the-loop: запросы доступа

Агент, упёршийся в запрет, не ретраит — он оставляет заявку:

```bash
rutile requests               # что просят агенты (id, путь, причина)
rutile approve a1b2c3d4 --for 1h --one-time
rutile reject a1b2c3d4
```

`rutile status` напомнит про неразобранные заявки.

### Мультиагентность: делегирование суб-агентам

Оркестратор может выпустить помощнику **суб-токен**, ограниченный
подмножеством своих путей и временем жизни (по умолчанию 1ч, максимум 24ч):

- реальный доступ ребёнка = *его паттерны ∩ живая политика родителя* —
  урезали или отозвали родителя, и все дети теряют доступ мгновенно;
- глубина = 1: суб-токен не может делегировать дальше и подавать заявки;
- в аудите ребёнок виден как `parent>label`.

```bash
rutile delegations              # кто кому что выдал и до какого времени
rutile delegations revoke <id>
```

### Минимизация раскрытия: rutile run

Rutile может передать секрет процессу, не возвращая само значение агенту:

```bash
rutile run -e API_KEY=dev/svc/key -- sh -c 'curl -H "X-Key: $API_KEY" https://api…'
rutile run --allow-argv-secrets -- deploy --token {{rutile:deploy/token}}
```

Предпочтителен `-e`: значение отсутствует в тексте команды и shell history.
Это не DLP-граница — дочерний процесс всё ещё может вывести или залогировать
свой env. Подстановка в argv по умолчанию запрещена, потому что argv виден в
process listings и telemetry; `--allow-argv-secrets` является явным принятием
этого риска. При `RUTILE_AGENT`/`RUTILE_TOKEN` чтение проходит через политику.

Размер значения ограничен **512 КиБ**. Rutile предназначен для credential и
небольших конфигурационных значений, а не для датасетов и произвольных blob.

### HTTP-режим и выделенный хост

MCP-сервер умеет streamable HTTP — для фреймворков без stdio и для
**сетевого развёртывания**: один rutile-хост обслуживает всех агентов сети,
у каждого свой токен, политика и след в аудите.

```bash
# локально, обычный HTTP (только loopback):
rutile mcp --http 127.0.0.1:7997

# выделенный хост, HTTPS (не-loopback ТРЕБУЕТ TLS):
rutile mcp --http 0.0.0.0:7997 --tls-cert cert.pem --tls-key key.pem
# клиенты шлют: Authorization: Bearer rtl_<токен агента>
```

Для выделенного хоста:

- не-loopback без TLS отвергается; `--insecure` — только внутри SSH-туннеля
  или доверенной сети (WireGuard);
- rate limiting на IP включён по умолчанию (`--rate-limit`, 120 req/min);
- **mTLS**: `--tls-client-ca ca.pem` требует проверенные клиентские
  сертификаты; `--spiffe-trust-domain <domain>` разрешает certificate-only
  аутентификацию для SPIFFE URI SAN `spiffe://<domain>/agent/<name>`. Без
  явного trust domain клиентский сертификат всё равно проверяется, но агенту
  нужен Bearer-токен;
- демон — через systemd-юнит из `contrib/`; после перезагрузки человек один
  раз делает `rutile unlock` по SSH — ключ не лежит на диске расшифрованным;
- mTLS gateway должен работать под uid владельца daemon: SPIFFE-assertions от
  других пользователей группового сокета отвергаются;
- сетевым токенам ставьте срок (`--expires 30d`), а локальные делайте
  `--local-only` — украденный локальный токен бесполезен по сети.

### Метаданные токена

Каждый токен знает, кто он, зачем и до какого времени:

```bash
rutile agent add claude --type claude-code --local-only
rutile agent add ci-runner --type ci --expires 30d -d "GitHub Actions deploy"
rutile agent list   # имя, тип, срок, local-only, активность
```

`--expires` (`30d`, `12h`) жёстко гасит токен; `--local-only` делает его
недействительным на HTTP-транспорте, даже если он украден. Суб-токены
наследуют ограничения родителя.

### Совместимость с агентами

| Клиент | Как |
|---|---|
| Claude Code / Claude Desktop | MCP stdio (`rutile mcp`) или плагин из репо |
| Cursor, Windsurf, Zed, Cline / Roo Code, Continue | MCP stdio |
| OpenAI Agents SDK, LangChain / LangGraph, CrewAI, AutoGen | MCP (stdio или streamable HTTP) |
| Удалённые / кастомные фреймворки | streamable HTTP + Bearer-токен |
| Всё, что вообще без MCP | `rutile run` (env/placeholder-инъекция)

## Плагин для Claude Code

Репозиторий одновременно является плагином Claude Code: после установки
Claude получает подключение MCP-сервера (`.mcp.json`), skill с безопасным
workflow и две команды — `/rutile:secrets-setup` (пошаговая настройка) и
`/rutile:secrets-status` (состояние, заявки, свежий аудит). Достаточно
задать `RUTILE_AGENT`/`RUTILE_TOKEN` в окружении — остальное
автоматически.

## Аудит

Выдача секрета и списка блокируется, если audit-запись нельзя надёжно
дописать. Hash-chain обнаруживает правку или удаление строк, но не защищает от
владельца файла, способного пересчитать всю цепочку; для такого threat model
финальный hash нужно экспортировать во внешнее append-only хранилище.

```bash
rutile audit             # последние записи: кто, что, когда, granted/denied
rutile audit verify      # проверка целостности
rutile audit rotate      # архив; новая цепочка связана checkpoint-записью
```

## Ротация ключа и бэкап

```bash
rutile rotate        # новый age-ключ + перешифровка всего хранилища
rutile backup <dir>  # копия зашифрованного ключа (храните отдельно от passphrase)
rutile doctor        # диагностика всей установки
```

При rotate первый отличный старый ключ остаётся в `identities.age.bak`, а
последующие отличающиеся recovery-копии получают имена
`identities.age.bak-*`. CLI печатает точный путь. Ротация использует
двухфазный dual-recipient переход: в каждой точке сбоя текущий `identities.age`
читает весь store; финальный проход удаляет старого recipient.

## Устройство

<p align="center">
  <img src="assets/architecture.svg" alt="Клиенты (CLI, MCP stdio, MCP HTTP) ходят в демон rutile через unix-сокет 0600; только демон держит расшифрованный ключ в памяти; на диске всё зашифровано или без секретов" width="880">
</p>


```
~/.rutile/               # git-репозиторий (auto-commit на каждое изменение)
├── store/**.age            # секрет = отдельный age-файл (layout как в pass)
├── identities.age          # приватный ключ, зашифрован passphrase (scrypt)
├── recipients.txt          # публичный ключ для шифрования
├── agents/<name>.yaml      # агенты: sha256 токена (сам токен не хранится)
├── policy.yaml             # правила доступа
├── audit.log               # hash-chained JSONL       (не коммитится)
├── requests.yaml           # заявки агентов            (не коммитится)
├── delegations.yaml        # живые суб-токены          (не коммитится)
└── daemon.sock / daemon.log
```

Один бинарник, три роли: CLI, демон (`rutile daemon`, авто-спавн;
launchd/systemd-юниты — в `contrib/`) и MCP-сервер (`rutile mcp`).
Демон — единственная граница доверия: только он держит расшифрованный ключ
в памяти (модель ssh-agent) и принимает policy-решения. Протокол —
newline-delimited JSON по unix-сокету 0600. `rutile git <...>` — любой
git в каталоге хранилища: `rutile git remote add origin … && rutile
git push`.

### System mode: настоящая граница привилегий

По умолчанию демон работает от вашего имени (модель ssh-agent — guardrails,
не клетка). На общем или выделенном хосте границу можно сделать настоящей:

```bash
# от выделенного пользователя (например _rutile), хранилище принадлежит ему:
rutile daemon --socket-mode 0660 --admin-uid 501
```

Для systemd используйте `contrib/rutile-daemon@.service` как
`rutile-daemon@<admin-uid>.service`; HTTPS/mTLS gateway из
`contrib/rutile-mcp.service` запускается под тем же выделенным uid.

Ключевой материал теперь лежит под uid, которого у агентов нет; сокет
доступен группе для агентских (токен) вызовов, а **human-операции
проверяются по peer credentials** (SO_PEERCRED / LOCAL_PEERCRED): unlock,
запись секретов и правку политики получают только `--admin-uid` и root.
Процесс под любым другим uid получит `forbidden`, даже дотянувшись до
  сокета. SPIFFE identity дополнительно принимается только от локального uid
  владельца daemon или root.

## Честная модель безопасности

- **Политика — это guardrails, а не клетка.** Любой процесс под *вашим* uid
  может обратиться к сокету с правами человека и обойти политику. Она
  защищает от ошибок и лишней инициативы добросовестного агента и даёт
  audit trail — но не от злонамеренного кода, уже запущенного от вашего
  имени. Та же модель доверия, что у ssh-agent/gpg-agent. Настоящая
  изоляция — демон под отдельным uid или ключ в железе. Подробнее —
  [SECURITY.md](SECURITY.md).
- От *других пользователей* машины защищает (0600 на сокете и файлах).
- `--one-time`/`--for` ограничивают окно доступа, но не «отзывают» уже
  выданное значение.
- Из-за Go GC зануление секретов в памяти не гарантировано.
- Не-loopback HTTP без TLS запрещён; `--insecure` допустим только как явное
  исключение внутри защищённого туннеля.

## Roadmap

- TLS-перехватывающий прокси с инъекцией кредов (стиль Agent Vault) —
  агент не видит секрет даже как плейсхолдер;
- аппаратно защищённый ключ (Secure Enclave);
- публичный релиз: GitHub, goreleaser, homebrew tap (конфиги уже в репо).

## Разработка

```bash
make test          # юнит- и интеграционные тесты
make test-linux    # тот же набор на Linux в Docker
make smoke         # сквозной сценарий в песочнице (scripts/smoke.sh)
make release-check # всё, что должно быть зелёным перед релизом
```

Tag `v*` запускает GitHub workflow: четыре платформенных архива и архив
исходников, CycloneDX SBOM для каждого бинарного архива, `checksums.txt` и
GitHub provenance attestations. Наличие этого конфига не доказывает, что
публичный или подписанный релиз уже опубликован: проверяйте страницу release и
attestations отдельно.

Переменные окружения: `RUTILE_DIR` (по умолчанию `~/.rutile`),
`RUTILE_SOCKET`, для агентов — `RUTILE_AGENT` / `RUTILE_TOKEN`.

## Лицензия

MIT

---

<p align="center">
  <img src="assets/logo.svg" width="36" alt=""><br>
  <sub><code>© rutile contributors · MIT</code></sub>
</p>
