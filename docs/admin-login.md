# Admin login

## First login and password setup

1. Open `/admin` over HTTPS.
2. Select **Токен / первый вход** and enter your existing `ADMIN_TOKEN` (or a token
   from `ADMIN_ACCOUNTS_JSON`). Supply TOTP if enabled.
3. Optionally enter a new password, at least 12 bytes. This sets the password for
   the authenticated account without changing ADMIN_TOKEN or KEY_STORE_SECRET.
4. Leave **Запомнить меня на 30 дней** enabled on a trusted personal device.
5. Afterwards use **Логин и пароль**. The legacy ADMIN_TOKEN account's login is
   `owner`; multi-admin accounts use their configured `name`. Fields support
   browser/password-manager autocomplete. The token remains a recovery method.

You can set/change a password later with **Пароль и доступ** in the top bar.
Changing it requires the current password or token and the current TOTP if enabled.
Password confirmation happens in the form. A failed confirmation does not log you
out. The recovery token is still a valid powerful credential: store it safely,
and don't discard KEY_STORE_SECRET, especially if it defaults to ADMIN_TOKEN.

Password login does not replace gateway client `arp_` API keys. These credentials,
provider settings and proxy authentication remain separate.

## Browser session

The browser receives an opaque HttpOnly, SameSite=Strict cookie scoped to
`/api/admin`. It is Secure on deployed hosts, including when Dokploy terminates TLS
and forwards HTTP internally. Only localhost HTTP development permits a non-Secure
cookie. No forwarded-proto header is trusted. Use HTTPS on a hosted domain; a
plain-HTTP remote host will not persist/send the Secure session cookie.

- Remembered session: 30 days, including browser restarts.
- Without Remember me: browser-session cookie, maximum server lifetime 12 hours.
- **Выйти** revokes the server session and expires its cookie, rather than merely
  clearing browser state.
- New browser login no longer puts bearer tokens or passwords in sessionStorage.
  Existing legacy header sessions are supported until expiry for compatibility.
- Password change revokes other browser/header sessions for that account. The
  current browser receives a new session.
- Changing configured name/token/role/TOTP invalidates matching remembered sessions
  and saved password bindings; re-bootstrap with the current configured token.
- Invalid/expired sessions show the login form; a transient server error does not
  intentionally wipe a valid browser session.

Cookies authenticate only the administrative API, not `/v1` requests. Cookie-based
mutations require `X-Admin-CSRF: 1` and reject explicit foreign Origin headers.
TOTP is required at login/password changes but is not re-entered on every request.

## Storage and deployments

Passwords are salted PBKDF2-HMAC-SHA256 hashes (600,000 iterations, 16-byte random
salt, 32-byte hash); plaintext passwords/tokens are not stored in the key store.
Remembered sessions store only SHA-256 digests of 32-byte random bearers with their
expiry and account/password-version binding. They are bounded to 100 active entries;
old/expired entries can be removed when another session is created.

These optional `admin_passwords`/`admin_sessions` fields live in the existing v2
key store. File startup and PostgreSQL state hydration preserve sessions across
redeployments when the same persistent state and account configuration are kept.
Redis is not required for new browser sessions. Regular backup export includes
password hashes but **excludes active browser sessions**; backup restore revokes
sessions. Protect backups, since password hashes permit offline guessing.

No new encryption key/database tables/dependency are introduced. Existing stores
without these fields still load. Old binaries can drop the optional login settings
when saving; preserve an upgraded backup before rollback. For stateless/locked stores,
new persistent browser login returns a clear error; the existing API token/header
session workflow remains available.

This does not add distributed concurrent state transactions. Multiple replicas
writing independent copies of the existing JSON state can overwrite each other's
session/password updates, just like other gateway settings; deploy a single state
writer until that architecture is addressed separately.

Login/password attempts are bounded per process (10 per remote peer per minute),
and expensive password hashing has two concurrent slots. Behind Dokploy, the peer
may be the reverse proxy, so many admins may share the same throttle. Add trusted
edge rate limits as well; forwarded client-IP headers are not trusted automatically.

## API compatibility

`POST /api/admin/login` supports the original `{token,totp}` and still returns the
legacy 12-hour `session` for header-based clients. New browser requests send
`{browser:true,remember:true,name,password,totp}` or `{browser:true,token,totp}`,
with `X-Admin-CSRF: 1`. Initial token login may include `new_password` to bootstrap
an account without a saved password. Browser replies set the cookie and return
expiry/account/password_set, never the session bearer.

`POST /api/admin/password`: `{password,current_password?,token?,totp?}` changes only
the authenticated account's password after reauthentication. `viewer` may manage
its own password and logout but cannot mutate providers/keys/routing.

`POST /api/admin/logout` revokes the current cookie/header session; returns 204.
`GET /api/admin/status` includes `admin.password_set`. Existing admin API callers
can continue using `X-Admin-Token` plus TOTP or legacy `X-Admin-Session` headers.
