# AgentRouter Unified Proxy

Один Go-процесс объединяет преобразование OpenAI Chat Completions → Responses API,
обратное преобразование ответов/SSE и upstream-прокси с профилями заголовков и
автоматическим хранением WAF-cookie.

## Запуск

```bash
cp .env.example .env
go run .
```

Или Docker:

```bash
docker build -t agentrouter-unified-proxy .
docker run --rm -p 8080:8080 --env-file .env agentrouter-unified-proxy
```

### Windows PowerShell

Сначала перейдите именно в каталог проекта — `Dockerfile` и `.env.example`
находятся там, а не в домашнем каталоге пользователя:

```powershell
Set-Location 'C:\programming\AgentRouterWAFSpoofing-Proxy'
Copy-Item .env.example .env
docker build -t agentrouter-unified-proxy .
docker run --rm --name agentrouter-unified-proxy -p 8080:8080 --env-file .env agentrouter-unified-proxy
```

Для многострочной команды PowerShell использует обратный апостроф (backtick)
`` ` ``, а не обратный слеш `\`:

```powershell
docker run --rm `
  --name agentrouter-unified-proxy `
  -p 8080:8080 `
  --env-file .env `
  agentrouter-unified-proxy
```

Проверка из второго окна PowerShell:

```powershell
curl.exe http://localhost:8080/health
```

API:

- `POST /v1/chat/completions` — преобразуется в Responses API и отправляется на
  `${UPSTREAM_URL}/v1/responses`; ответ преобразуется обратно, включая SSE.
- `POST /v1/responses` — прозрачно отправляется на тот же upstream endpoint.
- `GET /health` — состояние сервиса и наличие WAF-cookie (значение cookie не
  раскрывается).

`Authorization` передаётся upstream без изменения. Ключ в конфигурации прокси не
хранится. Максимальный размер JSON-запроса — 20 MiB.

## Конфигурация

| Переменная | По умолчанию | Описание |
|---|---|---|
| `UPSTREAM_URL` | `https://agentrouter.org` | Origin upstream-сервиса |
| `PORT` | `8080` | Порт прослушивания |
| `SPOOF_PROFILE` | `claude-code` | `claude-code` или `codex` |

Переменные процесса имеют приоритет над значениями из `.env`.

## Пример

```bash
curl -N http://localhost:8080/v1/chat/completions \
  -H 'Authorization: Bearer YOUR_AGENTROUTER_KEY' \
  -H 'Content-Type: application/json' \
  -d '{"model":"MODEL","messages":[{"role":"user","content":"Hello"}],"stream":true}'
```

Используйте сервис только с учётной записью и upstream, к которым у вас есть
разрешённый доступ.
