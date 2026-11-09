# AgentRouter Unified Proxy

Один Go-процесс объединяет:

- multi-upstream OpenAI-compatible gateway: нативный Chat Completions и Responses;
- OpenAI Chat Completions → Responses API adapter для Responses-only upstream;
- обратную конвертацию обычных и SSE-ответов;
- streaming tool calls, vision, structured output и reasoning;
- spoof-профили `claude-code` / `codex`;
- получение и ротацию WAF-cookie AgentRouter.

Provider задаёт Base URL, protocol и список моделей; API-ключ выбирает существующего
провайдера и хранит credential, routing policy и network route. Старые unlinked
ключи сохраняют собственные настройки. Chat-запрос идёт нативно на Chat upstream
либо через существующий Responses adapter.
Входящие credentials используются только с default upstream в legacy режиме.

Подробная инструкция, ограничения безопасности, обновление и откат:
[`docs/multi-upstream.md`](docs/multi-upstream.md).

Исходящие HTTP/HTTPS CONNECT и SOCKS5 прокси, привязки ключей и автоматическое
перераспределение: [`docs/network-proxies.md`](docs/network-proxies.md).
Панель разделена на Overview, Providers, API keys, Network proxies, Client access и Events.
Привязка моделей к API и выбор провайдера при добавлении ключа:
[`docs/providers.md`](docs/providers.md).

## Возможности

- один статический Go-бинарник без runtime-зависимостей;
- исходящие HTTP/HTTPS/SOCKS5 network proxies с encrypted auth и stable key bindings;
- автоматическое распределение ключей с минимальными перемещениями, без hard limit;
- Providers с явным model catalog: зарегистрированная модель идёт только к её провайдерам;
- `POST /v1/chat/completions` и `POST /v1/responses`;
- `GET /v1/models` и alias `GET /models`;
- SSE с немедленным flush и idle-timeout;
- восстановление tool arguments из `arguments.delta`, `arguments.done`,
  `output_item.done` и terminal `response.completed.output`;
- stateless Responses requests (`store:false`) и автоматическое восстановление
  после Azure cross-resource item errors;
- WAF warmup, безопасное конкурентное cookie-хранилище и retry после WAF block;
- настраиваемые transport/5xx retries;
- optional `X-Proxy-Token` authentication;
- JSON-логи и сквозной `X-Request-ID`;
- Prometheus endpoint `/metrics`;
- graceful shutdown, CORS и лимит размера тела;
- CI и multi-architecture GHCR images (`linux/amd64`, `linux/arm64`).

## Быстрый запуск

### Windows PowerShell

```powershell
Set-Location 'C:\programming\AgentRouterWAFSpoofing-Proxy'
Copy-Item .env.example .env
docker build -t agentrouter-unified-proxy .
docker run -d --name agentrouter-unified-proxy --restart unless-stopped -p 127.0.0.1:8080:8080 --env-file .env -v agentrouter-proxy-data:/data agentrouter-unified-proxy
```

Проверка:

```powershell
curl.exe http://127.0.0.1:8080/health
curl.exe http://127.0.0.1:8080/metrics
```

Web-панель:

```text
http://127.0.0.1:8080/admin
```

После настройки `.env` можно использовать Compose:

```powershell
docker compose up -d --build
```

PowerShell использует обратный апостроф (backtick) `` ` `` для переноса команд,
а не `\`, применяемый в Bash.

### Go

```bash
cp .env.example .env
go run ./cmd/proxy
```

### Готовый образ GHCR

После публикации release tag (`v1.0.0` и т.п.):

```bash
docker pull ghcr.io/kevji1337/agentrouter-unified-proxy:latest
```

## Настройка клиента

Для OpenAI-совместимой IDE:

```text
Base URL: http://127.0.0.1:8080/v1
API Key: ваш ключ AgentRouter
```

Responses API доступен по адресу:

```text
http://127.0.0.1:8080/v1/responses
```

Если IDE работает в другом Docker-контейнере, используйте
`http://host.docker.internal:8080/v1` и публикуйте порт как `-p 8080:8080`, а не
только на `127.0.0.1`.

## Endpoints

| Метод | Путь | Назначение |
|---|---|---|
| `POST` | `/v1/chat/completions` | Native Chat или Chat → Responses → Chat по protocol key |
| `POST` | `/v1/responses` | Прозрачный Responses API proxy |
| `GET` | `/v1/models`, `/models` | Upstream model discovery |
| `GET` | `/health` | WAF-cookie и состояние сервиса |
| `GET` | `/metrics` | Prometheus text format |
| `GET` | `/docs` | ReDoc API documentation |
| `GET` | `/openapi.json` | OpenAPI 3.1 schema |
| `GET` | `/admin` | Web-панель управления |
| `GET/POST` | `/api/admin/keys` | Список и добавление stored keys |
| `PATCH/DELETE` | `/api/admin/keys/{id}` | Включение, переименование и удаление |
| `POST` | `/api/admin/keys/{id}/test` | Проверка ключа через upstream |
| `PATCH` | `/api/admin/keys/{id}/policy` | Priority, weight, models, limits и pricing |
| `GET/POST` | `/api/admin/backup` | Encrypted export/import keys, proxies и bindings |
| `GET/POST` | `/api/admin/providers` | Список/создание API providers и model catalogs |
| `PATCH/DELETE` | `/api/admin/providers/{id}` | Изменение общего URL/protocol/models и удаление |
| `GET/POST` | `/api/admin/network-proxies` | Список и добавление сетевых proxy |
| `PATCH/DELETE` | `/api/admin/network-proxies/{id}` | Изменение/удаление и автоматическое перераспределение |
| `POST` | `/api/admin/network-proxies/{id}/test` | Bounded connectivity probe без API credential |
| `GET` | `/api/admin/logs` | Live audit/request events |
| `PATCH` | `/api/admin/settings` | Runtime routing mode |
| `GET/POST` | `/api/admin/client-keys` | Список и генерация клиентских API keys |
| `PATCH/DELETE` | `/api/admin/client-keys/{id}` | Enable/disable/delete client key |
| `POST` | `/api/admin/client-keys/{id}/reveal` | Раскрыть ключ через admin session |

## Конфигурация

Переменные процесса имеют приоритет над `.env`.

| Переменная | По умолчанию | Описание |
|---|---|---|
| `UPSTREAM_URL` | `https://agentrouter.org` | Upstream origin без `/v1/responses` |
| `LISTEN_ADDRESS` | `0.0.0.0` | Адрес внутри процесса/контейнера |
| `PORT` | `8080` | Порт HTTP-сервера |
| `SPOOF_PROFILE` | `claude-code` | `claude-code`, `codex` или `generic` для default upstream |
| `UPSTREAM_API_PROTOCOL` | `responses` | Protocol default/inbound endpoint: `responses` или `chat-completions`; старые stored keys остаются Responses |
| `UPSTREAM_ALLOWED_ORIGINS` | пусто | Production allowlist scheme+host+port через запятую; пусто = unrestricted |
| `FORCE_SEQUENTIAL_TOOLS` | `true` | Один tool call за ход для совместимости с IDE |
| `STATELESS_RESPONSES` | `true` | Удалять Azure resource-bound state до отправки Responses requests |
| `PROXY_AUTH_TOKEN` | пусто | Требовать `X-Proxy-Token` на API и metrics |
| `ADMIN_TOKEN` | пусто | Включить и защитить web-панель/API управления |
| `KEY_STORE_SECRET` | `ADMIN_TOKEN` | Секрет AES-GCM шифрования key store |
| `KEY_STORE_PATH` | `data/keys.json` (`/data/keys.json` в Docker) | Файл зашифрованного key pool |
| `KEY_SELECTION_MODE` | `inbound-first` | `inbound-first`, `pool-first` или `pool-only` |
| `KEY_FAILOVER` | `true` | Переключать stored key после 401/402/429 |
| `KEY_COOLDOWN` | `5m` | Временно исключать ключ после 401/402/429 |
| `KEY_HEALTH_INTERVAL` | `5m` | Период background health-check enabled keys |
| `ADMIN_ACCOUNTS_JSON` | пусто | Multi-admin RBAC (`admin`/`viewer`) и Base32 TOTP |
| `RESPONSE_HEADER_TIMEOUT` | `5m` | Ожидание upstream response headers |
| `SSE_IDLE_TIMEOUT` | `10m` | Максимальная пауза между байтами upstream body |
| `WARMUP_INTERVAL` | `3m` | Период обновления WAF-cookie |
| `MAX_RETRIES` | `2` | Максимум transport retries для GET/HEAD (и unsafe при opt-in) |
| `RETRY_UNSAFE_REQUESTS` | `false` | Явно разрешить transport retries POST и других unsafe методов; возможен двойной биллинг |
| `RETRY_DELAY` | `1s` | Базовый exponential backoff |
| `RETRY_ON_5XX` | `false` | Retry HTTP 5xx |
| `MAX_BODY_BYTES` | `20971520` | Лимит request/converted response |

> `RETRY_ON_5XX=true` может повторно отправить уже принятый upstream запрос и
> привести к двойному биллингу токенов. По умолчанию выключено.

### Защита прокси

Укажите в `.env`:

```dotenv
PROXY_AUTH_TOKEN=replace-with-a-long-random-value
```

После этого клиент должен добавлять отдельный заголовок:

```text
X-Proxy-Token: replace-with-a-long-random-value
```

`Authorization: Bearer ...` остаётся ключом AgentRouter и не используется как
proxy token. `/health` намеренно доступен без token для Docker HEALTHCHECK.

## Web-панель и пул API-ключей

Добавьте в `.env` два длинных случайных значения. Совместимый с Windows
PowerShell 5.1 скрипт (удаляет старые дубликаты управляемых строк):

```powershell
function New-RandomSecret {
  $bytes = New-Object byte[] 32
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

$adminToken = New-RandomSecret
$storeSecret = New-RandomSecret
$pattern = '^(ADMIN_TOKEN|KEY_STORE_SECRET|KEY_STORE_PATH|KEY_SELECTION_MODE|KEY_FAILOVER|KEY_COOLDOWN)='
$lines = @((Get-Content .env) | Where-Object { $_ -notmatch $pattern })
$settings = @('', "ADMIN_TOKEN=$adminToken", "KEY_STORE_SECRET=$storeSecret",
  'KEY_STORE_PATH=/data/keys.json', 'KEY_SELECTION_MODE=pool-first',
  'KEY_FAILOVER=true', 'KEY_COOLDOWN=5m')
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllLines((Resolve-Path .env).Path, [string[]]($lines + $settings), $utf8)
Set-Clipboard $adminToken
```

Эквивалентная конфигурация вручную:

```dotenv
ADMIN_TOKEN=replace-with-random-admin-token
KEY_STORE_SECRET=replace-with-independent-encryption-secret
KEY_STORE_PATH=/data/keys.json
KEY_SELECTION_MODE=pool-first
KEY_FAILOVER=true
KEY_COOLDOWN=5m
```

Пересоздайте контейнер с named volume:

```powershell
docker run -d --name agentrouter-unified-proxy --restart unless-stopped `
  -p 127.0.0.1:8080:8080 `
  --env-file .env `
  -v agentrouter-proxy-data:/data `
  agentrouter-unified-proxy
```

Откройте `http://127.0.0.1:8080/admin` и введите `ADMIN_TOKEN`. Панель позволяет:

- добавлять providers с названием, Base URL, API protocol, profile и явными моделями;
- выбирать готового провайдера, network route и enabled при добавлении credentials;
- управлять HTTP/HTTPS/SOCKS5 proxy endpoints и зашифрованными логином/паролем;
- выбирать automatic, pinned или direct route для каждого upstream key;
- включать, выключать и удалять;
- проверять подключение через optional upstream `/v1/models` (404/405/501 = inconclusive, не failure);
- задавать priority, weight и model allowlist;
- ограничивать daily requests и monthly budget;
- учитывать input/output tokens и стоимость по настраиваемым тарифам;
- видеть upstream URL/protocol, masked credential, usage, failures, cooldown и last used;
- просматривать live audit/request events и usage charts;
- экспортировать и импортировать encrypted backup;
- переключать routing policy без перезапуска;
- контролировать WAF status и background key health.

Полные ключи никогда не возвращаются API панели и не пишутся в логи. На диске
они хранятся только как AES-GCM ciphertext. Смена `KEY_STORE_SECRET` без
повторного добавления ключей сделает существующий файл нечитаемым.

Multi-admin конфигурация поддерживает роли `admin` и `viewer`, а также
опциональный Base32 TOTP secret. UI после token+TOTP login использует 12-часовую
in-memory session; TOTP-код не хранится и не отправляется повторно.

### Клиентские API-ключи

В панели можно создать отдельный ключ вида `arp_...` для IDE или приложения.
Он используется как обычный OpenAI API key:

```http
Authorization: Bearer arp_...
```

Прокси проверяет его локально, удаляет клиентский credential перед upstream и
подставляет credential выбранного upstream из encrypted pool. Client keys можно раскрывать,
копировать, выключать и удалять; usage/last-used отображаются в панели.

Как только существует хотя бы один enabled client key, неизвестные Bearer keys
отклоняются с `401`. До создания первого ключа сохраняется прежний режим, чтобы
не заблокировать bootstrap панели. `PROXY_AUTH_TOKEN` остаётся дополнительным
аварийным токеном через `X-Proxy-Token`.

Режимы выбора:

- `inbound-first` — ключ IDE имеет приоритет; pool используется, если его нет;
- `pool-first` — сначала enabled key из pool, затем входящий ключ;
- `pool-only` — входящий `Authorization` игнорируется, используется только pool.

После добавления первого managed network proxy default/inbound fallback отключён:
используйте stored credentials с сетевыми привязками. Если все proxy отключены,
automatic keys возвращают `network_proxy_unavailable`, а не выходят напрямую.
Direct access можно разрешить явно в key policy.

В pool используется weighted round-robin. При `KEY_FAILOVER=true` ответы
401/402/429 переключают текущий запрос на следующий совместимый key, включая
другой Base URL/protocol. Исходный JSON готовится заново для каждой попытки.
`/v1/responses` не направляется на Chat-only providers; отсутствие подходящего
upstream возвращает `503 no_compatible_upstream`.

Ключи сначала фильтруются по enabled/cooldown/model/protocol/limits, затем выбирается
максимальный priority, а среди ключей одного priority применяется weighted
round-robin. Тарифы задаются в USD за миллион input/output tokens.

## Примеры

### Chat Completions

```powershell
$env:AGENTROUTER_API_KEY = "your-key"
curl.exe http://127.0.0.1:8080/v1/chat/completions `
  -H "Authorization: Bearer $env:AGENTROUTER_API_KEY" `
  -H "Content-Type: application/json" `
  --data-raw '{"model":"MODEL","messages":[{"role":"user","content":"Hello"}],"stream":true}'
```

### Models

```powershell
curl.exe http://127.0.0.1:8080/v1/models `
  -H "Authorization: Bearer $env:AGENTROUTER_API_KEY"
```

## Наблюдаемость

Каждый ответ содержит `X-Request-ID`. Входящий корректный `X-Request-ID`
сохраняется и отправляется upstream. Логи выводятся по одной JSON-записи на
строку и не содержат API keys, bodies или значения cookie.

Основные Prometheus metrics:

- `agentrouter_proxy_requests_total`;
- `agentrouter_proxy_errors_total`;
- `agentrouter_proxy_request_duration_seconds`;
- `agentrouter_proxy_active_sse`;
- `agentrouter_proxy_waf_cookie_present`;
- `agentrouter_proxy_waf_refreshes_total`;
- `agentrouter_proxy_retries_total`.

## Разработка

```bash
gofmt -w cmd/proxy/*.go internal/app/*.go
go vet ./...
go test ./...
go test -race ./...
docker build -t agentrouter-unified-proxy .
```

## Структура проекта

```text
cmd/proxy/                 entry point
internal/app/              proxy, conversion, auth, key pool, metrics
internal/app/assets/       embedded administration UI
deploy/                    Caddy and host Compose templates
docs/                      deployment documentation
.github/workflows/         CI and multi-arch image publishing
```

Для установки на VPS используйте [`docs/hosting.md`](docs/hosting.md). Готовый
шаблон Caddy автоматически выпускает TLS-сертификат и не публикует внутренний
порт прокси напрямую.

Для Dokploy используйте отдельную инструкцию [`docs/dokploy.md`](docs/dokploy.md):
источник GitHub, root `Dockerfile`, container port `8080` и persistent volume
на `/data`.

## PostgreSQL, Redis и alerts

`STORAGE_BACKEND=postgres` сохраняет encrypted gateway state и audit events в
PostgreSQL; при первом запуске существующий `/data/keys.json` автоматически
импортируется. Redis хранит distributed admin sessions, alert cooldown и active
request counters для least-loaded routing между replicas.

```dotenv
STORAGE_BACKEND=postgres
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
ALERT_COOLDOWN=5m
```

Telegram получает deduplicated alerts о key failover, WAF/Azure retries,
отсутствии доступных ключей и недоступности PostgreSQL/Redis.

Каждый upstream key может иметь собственные `base_url`, `api_protocol`, `spoof_profile`, model
allowlist, priority, weight и limits. Это позволяет объединять AgentRouter и
другие OpenAI-compatible endpoints в одном gateway.

Примеры клиентов находятся в `sdk/python`, `sdk/typescript` и `sdk/go`.

GitHub Actions выполняет format check, vet, race tests и Docker build. Tag вида
`v1.0.0` публикует multi-arch image в GHCR.

## Лицензия и third-party notices

Проект распространяется по MIT License. Сведения о референсных проектах
находятся в [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

Используйте сервис только с upstream и учётной записью, к которым у вас есть
разрешённый доступ.
