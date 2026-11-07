# AgentRouter Unified Proxy

Один Go-процесс объединяет:

- OpenAI Chat Completions → Responses API;
- обратную конвертацию обычных и SSE-ответов;
- streaming tool calls, vision, structured output и reasoning;
- spoof-профили `claude-code` / `codex`;
- получение и ротацию WAF-cookie AgentRouter.

Прокси всегда отправляет генерацию на `${UPSTREAM_URL}/v1/responses` и передаёт
входящий `Authorization` без изменения.

## Возможности

- один статический Go-бинарник без runtime-зависимостей;
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
go run .
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
| `POST` | `/v1/chat/completions` | Chat → Responses → Chat conversion |
| `POST` | `/v1/responses` | Прозрачный Responses API proxy |
| `GET` | `/v1/models`, `/models` | Upstream model discovery |
| `GET` | `/health` | WAF-cookie и состояние сервиса |
| `GET` | `/metrics` | Prometheus text format |
| `GET` | `/admin` | Web-панель управления |
| `GET/POST` | `/api/admin/keys` | Список и добавление stored keys |
| `PATCH/DELETE` | `/api/admin/keys/{id}` | Включение, переименование и удаление |
| `POST` | `/api/admin/keys/{id}/test` | Проверка ключа через upstream |

## Конфигурация

Переменные процесса имеют приоритет над `.env`.

| Переменная | По умолчанию | Описание |
|---|---|---|
| `UPSTREAM_URL` | `https://agentrouter.org` | Upstream origin без `/v1/responses` |
| `LISTEN_ADDRESS` | `0.0.0.0` | Адрес внутри процесса/контейнера |
| `PORT` | `8080` | Порт HTTP-сервера |
| `SPOOF_PROFILE` | `claude-code` | `claude-code` или `codex` |
| `FORCE_SEQUENTIAL_TOOLS` | `true` | Один tool call за ход для совместимости с IDE |
| `STATELESS_RESPONSES` | `true` | Удалять Azure resource-bound state до отправки Responses requests |
| `PROXY_AUTH_TOKEN` | пусто | Требовать `X-Proxy-Token` на API и metrics |
| `ADMIN_TOKEN` | пусто | Включить и защитить web-панель/API управления |
| `KEY_STORE_SECRET` | `ADMIN_TOKEN` | Секрет AES-GCM шифрования key store |
| `KEY_STORE_PATH` | `data/keys.json` (`/data/keys.json` в Docker) | Файл зашифрованного key pool |
| `KEY_SELECTION_MODE` | `inbound-first` | `inbound-first`, `pool-first` или `pool-only` |
| `KEY_FAILOVER` | `true` | Переключать stored key после 401/402/429 |
| `KEY_COOLDOWN` | `5m` | Временно исключать ключ после 401/402/429 |
| `RESPONSE_HEADER_TIMEOUT` | `5m` | Ожидание upstream response headers |
| `SSE_IDLE_TIMEOUT` | `10m` | Максимальная пауза между байтами upstream body |
| `WARMUP_INTERVAL` | `3m` | Период обновления WAF-cookie |
| `MAX_RETRIES` | `2` | Число transport retries |
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

- добавлять ключи (enabled/disabled при создании);
- включать, выключать и удалять;
- проверять ключ через upstream `/v1/models`;
- видеть masked credential, usage, failures и last used;
- контролировать WAF status и routing policy.

Полные ключи никогда не возвращаются API панели и не пишутся в логи. На диске
они хранятся только как AES-GCM ciphertext. Смена `KEY_STORE_SECRET` без
повторного добавления ключей сделает существующий файл нечитаемым.

Режимы выбора:

- `inbound-first` — ключ IDE имеет приоритет; pool используется, если его нет;
- `pool-first` — сначала enabled key из pool, затем входящий ключ;
- `pool-only` — входящий `Authorization` игнорируется, используется только pool.

В pool используется round-robin. При `KEY_FAILOVER=true` ответы 401, 402 и 429
переключают текущий запрос на следующий enabled key.

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
gofmt -w *.go
go vet ./...
go test -race ./...
docker build -t agentrouter-unified-proxy .
```

GitHub Actions выполняет format check, vet, race tests и Docker build. Tag вида
`v1.0.0` публикует multi-arch image в GHCR.

## Лицензия и third-party notices

Проект распространяется по MIT License. Сведения о референсных проектах
находятся в [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

Используйте сервис только с upstream и учётной записью, к которым у вас есть
разрешённый доступ.
