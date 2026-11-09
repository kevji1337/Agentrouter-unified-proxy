# Providers and model routing

## Workflow

1. Open `/admin` → **Providers** → **Add provider**.
2. Enter its name, actual API Base URL, configured API protocol (`responses` or
   `chat-completions`), request profile and explicit model IDs.
3. Models can be entered one per line or comma-separated. Add/remove IDs through
   **Edit models**. No automatic capability detection, aliases or model renaming.
4. Open **API keys** → **Add API key**, choose the existing provider and enter the
   upstream credential. Choose automatic/pinned/direct network routing separately.
5. Configure priority, weight and budgets per key in Routing and limits. All keys
   linked to a provider share its URL, API protocol, spoof profile and model catalog.
6. Use a managed client `arp_` key and `pool-only` on the client gateway. API keys
   do not have to be disclosed to client applications.

New UI credentials require an existing enabled provider. If none exists, Add API
key leads to Providers. Existing unlinked credentials are shown as **Legacy endpoint**
and continue to work. Their policy dialog can link them to a provider without
re-entering the encrypted API key, or keep the legacy endpoint settings. Network
proxy assignment and client access credentials are independent from providers.

## Model ownership rules

A provider's model list is an explicit allowlist, not a free-form label:

- `model-a` assigned only to API A → only keys linked to API A are eligible.
- `model-b` assigned only to API B → only keys linked to API B are eligible.
- The same ID in A and B → both may serve it; existing priority, weight, cooldown,
  model/protocol compatibility and key failover determine the selected credential.
- Provider disabled → its keys cannot serve requests. Its registered models remain
  reserved, so a catch-all legacy key cannot silently take over those requests.
- Empty provider catalog → **no generation models**, not all models. The provider
  can be created first and populated later. No `*` or wildcard prefix is accepted.
- Comparisons use exact IDs without case sensitivity, matching existing allowlist
  behavior. The original model field is sent unchanged; there is no alias adapter.

For any ID registered in at least one provider, unlinked legacy keys and default
inbound credentials are excluded even when their old allowlist is empty or their
priority is higher. If all eligible credentials are disabled, exhausted, cooling
or absent, the request fails with the existing 503 routing error; it does not
escape the configured model owners. `/v1/responses` also requires a Responses
provider and returns `no_compatible_upstream` if none is available.

Unregistered model IDs preserve old behavior for legacy/unlinked keys: their
per-key allowlist or old default/inbound routing may still serve them. Removing
an ID from **every** provider removes its reservation. Use `pool-only` and migrate
all keys to providers if you require a completely explicit model catalog with no
legacy fallback. An empty managed-only catalog returns 503 for generation.

Priority, limits and network-route status continue to filter keys. Failover on
401/402/429 may choose another key of the same provider or another provider listing
that model. It never chooses an unrelated provider just because the first failed.
Chat requests use the chosen provider's actual configured protocol; Responses
requests never implicitly convert to Chat. Native JSON/SSE behavior is unchanged.

`GET /v1/models` remains a request to one selected upstream; it is not an aggregate
of this admin catalog. Adding a model ID is an operator declaration, not proof
that the remote provider supports it. Validate a real model request separately.

## Shared settings and compatibility

Provider owns name, Base URL, protocol, profile, enabled and model catalog. API key
owns encrypted credential, provider reference, priority/weight, budgets, usage and
network binding. New linked keys do not persist duplicate provider URL/protocol/
model settings; effective safe views show the shared values. Editing a provider
applies to all future selections, including key probes. Active HTTP requests/SSE
streams retain their previous selected settings. Changing provider URL does not
migrate remote state/resource IDs, and may send the linked API credential to the
new origin: only a trusted administrator should perform it.

An old policy client omitting `provider_id` preserves the link. For linked keys,
per-key URL/protocol/profile/models are ignored in favor of the provider. An
explicit empty `provider_id` unlinks the key; send the desired legacy endpoint
settings with that update. Deletion is rejected while any key references the
provider, including disabled keys. Disable the provider or reassign keys first.

Providers are optional entries in the existing v2 JSON and encrypted backup
payload (`providers` array, keys gain `provider_id`). No new database tables,
credential encryption scheme or secret is introduced. File/PostgreSQL stores
remain compatible with v1/v2 data lacking providers. Backup import rejects invalid
provider settings, duplicate IDs/names and missing provider references before
replacing the pool. Existing keys, usage, client keys and proxy auth are retained.

Do not run older binaries on the current provider/proxy-enabled store: they can
ignore routing ownership or erase unknown fields. Roll back using a separate
pre-upgrade copy, keeping the current encrypted backup and KEY_STORE_SECRET safe.

## Browser smoke check

`node scripts/admin-smoke.cjs` runs offline UI fixtures in Chrome at 1280px and
390px widths when `DELTA_SCRATCH_DIR` is available. Outside Delta supply a temporary
output directory: `node scripts/admin-smoke.cjs .admin-smoke`. Set `CHROME_BIN` if
Chrome/Chromium is not found automatically. The check exercises provider model
editing, provider selection in key creation, proxy forms, tabs, search and pages;
it also checks readable logs, filters and credential editing; it does not contact real upstreams. Screenshots/browser profiles are test outputs,
not credentials or production configuration; do not commit the output directory.

## Admin API

Provider reads are permitted to `viewer`; mutations require `admin`:

- `GET /api/admin/providers`: `{data:[...]}`. Provider views include shared settings
  and `keys`, the number of linked credentials. No API/proxy credentials.
- `POST /api/admin/providers`: create and return the provider (201).
- `PATCH /api/admin/providers/{id}`: replace shared fields; omitted enabled keeps
  its previous value. Name/Base URL required; omitted models clears the catalog,
  omitted protocol means Responses. UI always sends the complete configuration.
- `DELETE /api/admin/providers/{id}`: 204; fails if linked keys remain.
- `POST /api/admin/keys`: existing body with `policy.provider_id` to attach the key.
- `PATCH /api/admin/keys/{id}`: optional name/enabled/key for credential editing;
  omitted/empty replacement keeps the encrypted key. See [logging.md](logging.md).
- `PATCH /api/admin/keys/{id}/policy`: set `provider_id` to link/reassign; omitted
  preserves the reference, empty explicitly unlinks.

Provider supports up to 500 explicit model IDs, each at most 200 bytes without
whitespace/wildcards. URLs obey the same http(s) validation and process-owned
`UPSTREAM_ALLOWED_ORIGINS` as other API endpoints. Network proxy endpoints are
configured separately; see [network-proxies.md](network-proxies.md).

Example placeholders:

```json
{
  "name": "Provider A",
  "base_url": "https://api.provider-a.example/v1",
  "api_protocol": "chat-completions",
  "spoof_profile": "generic",
  "models": ["model-a", "model-b"],
  "enabled": true
}
```

```json
{
  "name": "Provider A primary key",
  "key": "REPLACE_WITH_API_KEY",
  "policy": {
    "provider_id": "ID_RETURNED_BY_PROVIDER_CREATE",
    "proxy_mode": "auto",
    "weight": 1
  }
}
```
