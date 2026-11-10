# Admin login

## Password-only panel

Open `/admin` over HTTPS and enter your configured account name and password.
The legacy ADMIN_TOKEN account name is `owner`; multi-admin accounts use their
configured `name`. Password fields support browser/password-manager autocomplete.
Leave **Запомнить меня на 30 дней** enabled only on a trusted personal device.
TOTP is still required if configured.

The panel no longer offers token login or token-based password confirmation.
Change your password with **Сменить пароль**, confirming the current password and
TOTP. Existing saved passwords and remembered cookies are unchanged by this update.
Password login does not replace gateway client `arp_` API keys.

For a new installation or forgotten password, the legacy administrative API still
supports authenticated token recovery/bootstrap. `POST /api/admin/login` with
`{token,totp,new_password}` and `X-Admin-CSRF: 1` can initially set a password when
none exists and returns a legacy header session, not a browser cookie. Use that
session with `POST /api/admin/password` and fresh token/TOTP confirmation to reset
an existing password. Do not place real secrets in a committed file or URL.

Keep ADMIN_TOKEN and KEY_STORE_SECRET: token access remains API-compatible and
KEY_STORE_SECRET may default to ADMIN_TOKEN. Removing/changing it can make saved
credentials unreadable. Token authentication is not a public browser-login option;
requests with `browser:true` require name/password and reject token/new_password.

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
- On reload, a neutral **Проверяем сессию…** screen is shown while status is fetched.
  The password form is hidden in the initial HTML; it appears only on a missing or
  expired session (401), so a remembered login does not flash the form.
- If the initial session check fails because of the network/server, the checking
  screen offers Retry; it does not show a misleading login form or clear the cookie.

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
`{browser:true,remember:true,name,password,totp}`, with `X-Admin-CSRF: 1`.
Browser token login is rejected. Legacy non-browser token login may include
`new_password` with the CSRF header to bootstrap an account without a saved password. Browser replies set the cookie and return
expiry/account/password_set, never the session bearer.

`POST /api/admin/password`: `{password,current_password?,token?,totp?}` changes only
the authenticated account's password after reauthentication. `viewer` may manage
its own password and logout but cannot mutate providers/keys/routing.

`POST /api/admin/logout` revokes the current cookie/header session; returns 204.
`GET /api/admin/status` includes `admin.password_set`. Existing admin API callers
can continue using `X-Admin-Token` plus TOTP or legacy `X-Admin-Session` headers.
