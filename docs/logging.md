# Readable request journal and credential editing

## Journal

`/admin` → **Журнал запросов / Events** shows a readable result instead of an
internal event name alone. Each LLM request includes method/endpoint, client HTTP
status, elapsed milliseconds, model, provider, key name/mask and selected network
route. Expand a row for request ID, upstream endpoint/status/protocol, attempts,
usage tokens (when returned), bytes and error code. Newest entries appear first.

Example (illustrative, not real traffic):

```text
POST /v1/chat/completions → HTTP 200 · 1250 мс
Модель: model-a · API: Provider A · Ключ: Primary (sk-••••TEST) · Маршрут: Outbound EU · SSE
```

- **Search**: model, provider, key name/mask, request ID, event or error code.
- **Level**: all, warnings/errors, errors only or information.
- **Category**: requests, routing/failover, tools, admin or system.
- **Background events**: successful admin GETs, model discovery, health summaries,
  WAF refreshes and individual successful tool emissions are hidden by default.
  Warnings/errors stay visible even when the event is normally background.
- **Pause / Continue**: stop automatic polling without stopping the gateway.
- **All events of this request**: filter by exact request ID, clear other filters
  and include background events; this exposes tools/retries leading to the result.
- Expanded details stay open when new events arrive. Refresh without new events
  does not rebuild the journal. Polling occurs only on the visible Events tab.

`parallel_tools_suppressed` explains that sequential compatibility forwarded only
one of multiple tools. It remains a warning; its behavior is not changed by logging.
Failover displays the previous/next provider and key, status and network routes;
the final request row contains the last route actually attempted. Health summaries
show accepted/failed/inconclusive counts; individual failed checks identify the key.

HTTP 4xx is warning and 5xx is error. If an SSE body fails after HTTP 200 headers
were sent, the record keeps status 200 but marks `response_interrupted` and the
bounded error code. HTTP success alone does not prove generation completed.
Mid-stream provider error events with a clean connection are not semantically
validated by the native passthrough and may still require inspecting the client.

Transport errors are classified as DNS/TLS/connection/timeout/cancellation without
logging the raw error text. Proxy 407 is identified separately from provider auth.
No request/response body, Authorization, X-Api-Key, proxy password or cookie value
is added to logs. Hosts and names are safe configured identifiers; don't put secrets
in display names/model IDs/request IDs. Query strings are omitted from logged
upstream paths. Existing remote client address remains part of the JSON record;
treat operational logs as private data.

## Storage, deployment and API

Machine-readable event names (`message`) remain unchanged for existing consumers
and Telegram alert matching. New additive fields are `summary`, `category` and
`background`, plus the request diagnostics. stdout and existing PostgreSQL audit
storage receive the same enriched records. No database migration is required.

The admin endpoint returns an **in-memory ring**, not the PostgreSQL audit archive:
500 events retained per process; filtering searches only the fetched local window.
Data is bounded, so heavy traffic can overwrite events while the UI is paused.
No full-history search, multi-replica aggregation or cross-deploy event persistence
is claimed. A seamless Dokploy deployment can replace the process; the UI notices
its instance ID and resets the cursor instead of waiting for the old sequence.
Repeated load-balancing between separate replicas will show separate process windows.

`GET /api/admin/logs?after=N&limit=100` keeps its `data` array and adds:

- `instance`: opaque ID of this process's log ring;
- `next_after`: last returned sequence for the next poll;
- `has_more`: additional incremental events remain;
- `reset`: supplied sequence was ahead of this process's ring.

Without `after` (or `after=0`), the endpoint returns the **latest** `limit` entries,
chronological within the response. Nonzero cursors fetch newer entries oldest-first.
Limit is 1–200 (default 100). Admin and viewer access remains protected by RBAC.

## Edit upstream API keys

**API keys → Edit** opens an explicit credential editor:

- rename the key;
- enable/disable it;
- optionally replace the API credential.

The old credential is never returned or filled into the form. An empty replacement
field preserves it. A successful replacement is freshly AES-GCM encrypted, updates
the safe mask and clears the old credential's cooldown/last error. Provider, network
binding, priority/weight, budgets and historical usage/failure counters are preserved.
Requests already using the old credential finish with their snapshot; future
selections use the new one. Use the existing policy button for provider/route/limits.

`PATCH /api/admin/keys/{id}` now accepts optional `key` alongside `name`/`enabled`.
Omitted/empty `key` means keep the stored credential; validation remains 8–4096
non-whitespace characters after trimming. Bad validation does not partially apply
name/enabled changes. Responses return only the safe key view. Credential editing
requires admin role; viewer cannot replace keys. Audit records contain only
`credential_replaced: true/false`, never the submitted secret.

## Verification

`node scripts/admin-smoke.cjs` exercises readable summaries, filters, background
visibility, request grouping, process change recovery, HTML escaping and credential
editing alongside provider/proxy UI at desktop/mobile widths. It uses offline fixture
data and no real credentials; set `CHROME_BIN` and a temporary output directory when
running outside Delta. Go integration tests verify real routing metadata and failover,
secret-safe errors, cursor behavior, concurrent log updates, encrypted replacement
and RBAC. These checks are not a live-host traffic test.
