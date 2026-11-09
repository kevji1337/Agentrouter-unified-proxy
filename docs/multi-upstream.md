# Multi-upstream gateway

## Добавление credentials

1. Настройте `ADMIN_TOKEN`, независимый `KEY_STORE_SECRET` и persistent `/data`.
2. Войдите в `/admin`, нажмите **Add key**.
3. Укажите Display name, API key, Upstream Base URL, API protocol и Enabled.
4. Для AgentRouter оставьте `https://agentrouter.org`, `responses`, Automatic.
5. Для стороннего API задайте его реальный Base URL и подтверждённый провайдером
   протокол. Automatic использует generic profile для другого origin; можно
   явно выбрать Generic OpenAI. Generic не добавляет AgentRouter spoof headers
   и не использует WAF cookies.
6. Через Routing and limits редактируйте URL, protocol, priority, weight, models,
   daily request limit, budget и pricing. Enable/disable, Test и Delete остаются
   в таблице. Несколько записей с разными названиями могут использовать один URL.
7. Создайте **Client API key** (`arp_...`) и используйте его в приложении:
   Base URL `http://localhost:8080/v1`, Authorization `Bearer arp_...`.
   Для multi-upstream рекомендуется `pool-only`.

UI показывает URL, protocol, masked credential, usage и статус. Полный upstream
API key не возвращается admin API. Client API keys — отдельные credentials:
их создание/reveal для администратора остаётся существующей возможностью.

### Admin API

`POST /api/admin/keys` сохраняет существующий контракт: upstream-настройки
передаются внутри `policy`. Пример **с placeholder, не с настоящим секретом**:

```json
{
  "name": "Provider A",
  "key": "REPLACE_WITH_PROVIDER_API_KEY",
  "enabled": true,
  "policy": {
    "base_url": "https://api.provider-a.example/api/v1",
    "api_protocol": "chat-completions",
    "spoof_profile": "generic",
    "priority": 10,
    "weight": 1,
    "models": ["MODEL_ID"]
  }
}
```

Protocol: только `responses` или `chat-completions`. При создании отсутствие
`api_protocol` означает `responses`, как в прежних версиях. При обновлении
`PATCH /api/admin/keys/{id}/policy` отсутствие поля сохраняет текущий протокол.
Остальные поля policy, как и раньше, являются полной заменой: присылайте текущие
настройки вместе с изменёнными полями. Пустой Base URL наследует `UPSTREAM_URL`.
Протокол stored key независим от `UPSTREAM_API_PROTOCOL`.

## Routing и совместимость

| Входящий endpoint | Upstream responses | Upstream chat-completions |
|---|---|---|
| `/v1/chat/completions` | Существующий Chat → Responses → Chat adapter | Нативный JSON/SSE passthrough |
| `/v1/responses` | Прямой Responses proxy, optional stateless sanitization | Исключается из выбора |
| `/v1/models` | Discovery на выбранном upstream | Discovery на выбранном upstream |
| Остальные существующие passthrough endpoints | Без нового adapter/capability detection | Без нового adapter/capability detection |

Конфигурация не обнаруживается по HTTP-ошибке и не переключается автоматически.
При отсутствии доступной Responses-совместимой записи для `/v1/responses`
возвращается `503`, `error.code=no_compatible_upstream`. Нет Responses → Chat
конвертации. Для Chat и остальных маршрутов недоступный pool возвращает `503`,
`no_enabled_api_keys`. Provider должен реально поддерживать настроенный protocol,
модель и используемые параметры; gateway не обещает поддержки Anthropic,
Gemini-native, Azure deployment-specific URL/auth или произвольных API adapters.

Сначала фильтруются enabled, cooldown, model allowlist, limits/budget и требуемый
protocol. Затем выбирается максимальный priority; среди одинакового priority —
weighted round-robin (weight=1 даёт обычный round-robin). С Redis сохраняется
существующая приблизительная least-loaded эвристика по active response bodies.
Model allowlist содержит точные IDs (сравнение без учёта регистра) или `*`;
пустой список разрешает все модели. Model aliases/remapping не реализованы.

Режимы:

- `inbound-first`: входящий upstream credential имеет приоритет и используется
  **только** с default `UPSTREAM_URL`; иначе pool. Для несовместимого default
  протокола выбирается совместимый pool.
- `pool-first`: сначала pool, затем совместимый default endpoint с входящим
  upstream credential.
- `pool-only`: только encrypted pool; входящий upstream credential игнорируется.

Клиентский `arp_` проверяется локально, не является upstream credential и не
может fallback на анонимный default endpoint при пустом/недоступном pool.
Для bootstrap без stored keys и client authentication старое анонимное поведение
`inbound-first` сохранено. Непустой, но неподходящий pool не обходится анонимным
запросом к default upstream.

При `KEY_FAILOVER=true` 401/402/429 исключают текущий stored key из этого запроса,
записывают failure/cooldown и выбирают другой совместимый key. Меняться могут
origin, prefix и protocol. Каждая попытка готовится из **исходного** запроса;
ответ обрабатывается по adapter последней попытки. При исчерпании ключей
возвращается последняя upstream ошибка. Число переключений дополнительно
ограничено размером pool в начале запроса, даже при одновременном добавлении keys.
Failover не отправляет входящий
credential на новый origin и не повторяет запрос после начала streaming.

### Retries

- Transport error: GET/HEAD могут повторяться до `MAX_RETRIES`; POST и другие
  потенциально изменяющие состояние методы по умолчанию **не повторяются**:
  upstream мог уже принять запрос.
- `RETRY_UNSAFE_REQUESTS=true` явно включает прежние transport retries для них.
  Это может вызвать повторное выполнение и двойной биллинг.
- `RETRY_ON_5XX=true` отдельно разрешает повторение HTTP 5xx, также с риском
  повторного выполнения. По умолчанию выключено.
- Existing AgentRouter WAF rejection и Responses Azure resource-state rejection
  могут восстановиться одной дополнительной попыткой каждый. WAF retries
  ограничены доверенным default origin и non-generic profile.
- 401/402/429 failover — предусмотренная `KEY_FAILOVER` политика для отказов,
  а не retry после неопределённого transport результата.

## URL и безопасность

Base URL — абсолютный `http(s)` URL без userinfo, query и fragment:

| Base URL | Chat upstream endpoint |
|---|---|
| `https://provider.example` | `/v1/chat/completions` |
| `https://provider.example/` | `/v1/chat/completions` |
| `https://provider.example/v1` | `/v1/chat/completions` |
| `https://provider.example/api/v1` | `/api/v1/chat/completions` |
| `https://provider.example/custom` | `/custom/v1/chat/completions` |

Responses использует такое же правило с `/responses`. Суффикс `/v1` не
дублируется; произвольные prefixes не удаляются. Не включайте endpoint
`/chat/completions` или `/responses` в Base URL.

В production задайте process-owned allowlist **всех разрешённых origins**, включая
default (если он используется), без path prefixes:

```dotenv
UPSTREAM_ALLOWED_ORIGINS=https://agentrouter.org,https://api.provider-a.example,https://llm.provider-b.example
```

Allowlist сравнивает scheme+host+port (без учёта регистра), применяется при admin
create/update, отправке, health-check и warmup, включая загруженные/imported keys.
Пустое значение сохраняет прежнее unrestricted поведение. Local endpoints
разрешены: в restricted режиме явно перечислите, например,
`http://127.0.0.1:9000`. Не разрешайте metadata service или untrusted origins.

**Origin allowlist не является полной защитой от DNS rebinding или SSRF через
скомпрометированный разрешённый сервис.** В production дополнительно ограничьте
network egress/firewall, private/metadata destinations и DNS; предоставляйте admin
доступ только доверенным операторам. Используйте TLS, client auth, VPN/IP policy.
HTTP годится для явно доверенных локальных endpoints, не для публичных credentials.

HTTP redirects не выполняются: 3xx возвращается клиенту. Gateway не переносит
Authorization на redirect destination. Клиент также не должен автоматически
следовать upstream redirect с gateway credential.

Pool-запрос устанавливает только Bearer выбранного upstream key; входящие
`X-Api-Key`, Cookie, X-Proxy-Token и произвольные spoof headers не пересылаются.
При legacy inbound credential режиме `X-Api-Key` поддерживается только на
default endpoint. WAF cookie capture/send ограничены exact default origin
(включая scheme и port) с non-generic profile; сторонние Set-Cookie не могут
отравить общий AgentRouter cookie store. Explicit spoof profile вне default
origin не разрешает доступ к его cookies.

Upstream HTTP status/body в native режимах сохраняются, включая ошибки:
не допускайте возврата secrets собственным upstream. Gateway transport/probe
ошибки не раскрывают URL, headers или credentials.

## Streaming, tools и usage

Нативный Chat сохраняет JSON, tool calls, provider-specific fields, статусы и
SSE bytes без Responses-specific обработки. Нет синтетического Chat stream,
если нативный upstream проигнорировал `stream=true`: клиент получает настоящий
ответ upstream. `FORCE_SEQUENTIAL_TOOLS` относится только к Responses adapter,
а не нативному Chat. Responses adapter сохраняет существующую обработку tools,
reasoning, vision, structured output и JSON-to-SSE fallback.

SSE немедленно flush-ится, idle timeout отменяет upstream request. Usage читает
Responses `input_tokens/output_tokens` и Chat `prompt_tokens/completion_tokens`
из JSON или SSE usage frame. Upstream должен действительно вернуть usage;
если Chat stream не содержит usage, запросите `stream_options.include_usage`.
Существующий usage capture ограничен последними 2 MiB response bytes; для очень
большого JSON или необычного SSE usage может отсутствовать. Billing/budget —
локальная оценка, не сверка с фактическим счётом провайдера.

## Проверка подключения

Test и background health-check отправляют только GET `/v1/models` к конкретному
upstream с его credential и timeout 15s. 2xx подтверждает только models endpoint,
**не** generation protocol. 404/405/501 возвращают `ok:false`,
`inconclusive:true`: models optional, credential/protocol остаются непроверенными.
Такая проверка не увеличивает failures, не снимает и не добавляет cooldown.
Отказы авторизации/лимитов по-прежнему обновляют health/cooldown. Probe не тратит
токены генерации; реальную совместимость проверяйте отдельным запросом модели.

## Обновление и откат

1. До обновления экспортируйте encrypted backup, сохраните `/data`, env и
   `KEY_STORE_SECRET`; для PostgreSQL сохраните также database backup.
2. Обновите бинарник/образ, сохраняя volume и тот же encryption secret.
3. Stores/backups v1/v2 читаются как раньше. Новое необязательное `api_protocol`
   добавлено в текущий v2 JSON без изменения AES-GCM, nonce, KDF или ciphertext.
   Старые записи и backups без protocol означают Responses; ничего не удаляется.
4. Проверьте старый AgentRouter маршрут, затем добавьте custom credentials.
5. Экспортируйте **новый** backup после изменений.

Старый бинарник не умеет native Chat и может удалить неизвестное поле
`api_protocol` при сохранении. **Не запускайте его на текущем multi-upstream
store.** Для отката используйте отдельную копию pre-upgrade volume/database и
старый образ; текущий store и новый backup сохраните неизменными для повторного
обновления. Новые credentials не потеряются в архиве, но Chat-only upstream
нельзя использовать старой версией. Если нужны новые keys при откате, переносите
только Responses-совместимые записи с корректными URL; не меняйте secret.

## Архитектурные границы и дальнейшие работы

Существующая сущность — API key + BaseURL + policy + protocol. Отдельная Provider
сущность не нужна. `doUpstreamWithMeta` выбирает key, `upstreamSettings` получает
настройки, `prepareUpstream` готовит endpoint/body для каждой попытки; существующие
converters остаются источником Responses compatibility.

PostgreSQL хранит тот же encrypted JSON; отдельной migration таблиц нет.
Redis counters — приблизительные, а не distributed reservations. Resource IDs
Responses/files/batches не переносятся между независимыми providers:
`STATELESS_RESPONSES=true` подходит только для запросов с полной историей;
для stateful/resource workflows нужна внешняя affinity или выделенный pool.
Catalog `/models` не агрегирует все providers. Passthrough endpoints не получают
нового capability detection. Эти расширения не реализованы в данной задаче.

Network proxy — отдельная будущая настройка, не API upstream:

- добавить optional reference сетевого маршрута к существующей key policy;
- хранить proxy auth в encrypted credentials, отдельно от API keys;
- выбирать/cache-ить `http.Transport` по network route перед отправкой;
- сохранить `prepareUpstream`, routing, adapters и протоколы без изменений;
- default transport по-прежнему работает без per-upstream proxy;
- отдельные bounded connectivity probes, запрет redirects и secret-safe errors;
- SOCKS5/CONNECT adapters и UI добавлять только вместе с соответствующими тестами.

Никакие SOCKS5/HTTPS proxy settings, libraries, pools или rotation сейчас не
добавлены. Существующее поведение Go transport с proxy environment не изменено.
