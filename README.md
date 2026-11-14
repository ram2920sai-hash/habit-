# NEXO — website backend and original frontend

NEXO keeps the original habit tracker interface and adds email password reset codes, persistent login, per-user preferences, and account isolation. This package contains no user database or credentials.

## Free website deployment: Render + Neon or Supabase

This version supports a cloud PostgreSQL database. Local SQLite remains available for development. On Render, DATABASE_URL is required so the app cannot accidentally save accounts on temporary disk.

1. Keep this source code on GitHub. Do not upload .env, data/, a database, or a virtual environment.
2. Create a free PostgreSQL project in Neon or Supabase. Copy its pooled connection URL into Render's private DATABASE_URL setting. For Supabase, choose the Session pooler for IPv4 compatibility. Use the database owner connection; this backend creates its tables and never exposes the database URL to browsers.
3. Create a Render Web Service from this repository. Select Python 3 and the Free instance type. Leave Root Directory blank when server.py is at the repository root.
4. Build: `pip install -r requirements.lock.txt`
5. Start: `uvicorn server:app --host 0.0.0.0 --port $PORT --no-proxy-headers`
6. Set PYTHON_VERSION=3.14.2 and NEXO_HTTPS=1. Set NEXO_ALLOWED_HOSTS to the exact assigned Render hostname and NEXO_PUBLIC_ORIGIN to its full HTTPS URL, with no trailing slash.
7. For email reset codes on Render Free, configure BREVO_API_KEY and EMAIL_FROM in Render's private environment settings. Verify the sender and enable transactional email in Brevo. The backend uses Brevo's HTTPS API; Render Free blocks standard SMTP connections. Sender approval/domain requirements and email usage limits are controlled by the provider.
8. Set the health-check path to /healthz, deploy, and check the logs. A successful deployment gives you one HTTPS link to share with friends. Never paste secrets into GitHub files or public logs.

The included render.yaml also defines these settings for a Render Blueprint. Supply private values in the Render dashboard. No cloud accounts, database, or email sender are created just by uploading this code.

On first startup, tables are created automatically. PostgreSQL connections verify the database server's TLS certificate. Supabase tables enable row-level security and remove browser-role permissions: this app uses its own backend sessions, not Supabase Auth or the public Data API. Keep the database owner credentials on the backend only.

Free hosts have limits: Render may sleep when idle, Neon limits storage/compute, and Supabase may pause an inactive free project. Keep separate private backups. The app's existing JSON export/restore can transfer one user's habits between deployments; changing DATABASE_URL alone does not copy an old SQLite database or existing account logins. No old user database is included in this repository.

Setup still requires your Render account, selected cloud database, and verified email sender/API key. Live deployment and actual email delivery must be checked after configuration.

## Run locally on Windows

Use Python 3.11 or newer (tested with Python 3.14). Extract the ZIP and open a terminal in `nexo`:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -m uvicorn server:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. Create an account using an email inbox you control. Restarting the server retains accounts, habits, settings, and login sessions in `data/nexo.db`. Logins last up to 30 days; logging out or resetting a password revokes them. A new login replaces that account's previous login session. Browser cookie clearing also requires login again.

Choose light or dark mode with the top bar button or Settings → Appearance. Preferences are stored on the server for each account.

## Configure password reset email

Edit the private `.env` file or your host's secret environment variables:

- `SMTP_HOST`: your provider's SMTP hostname.
- `SMTP_PORT`: usually 587 with `SMTP_SECURITY=starttls`, or 465 with `SMTP_SECURITY=ssl`.
- `SMTP_FROM`: an approved sender address.
- `SMTP_USERNAME` and `SMTP_PASSWORD`: your provider's SMTP login and app password/API key.

TLS with certificate verification is required. SMTP credentials are never sent to the browser. Do not put `.env` in source control or share it. No real sender credentials are included. Obtain the precise SMTP values from your email provider, and use its required sender/domain verification.

Click **Forgot password?**, enter your account email, click **Send email code**, check that mailbox on your laptop (including spam), and enter the eight-digit code and new password. Codes expire in ten minutes, allow five guesses, and can be redeemed once. Requesting another code replaces the previous one. There are at most three requests per email every fifteen minutes. Unknown and registered emails receive the same response. If SMTP is missing, the interface clearly reports that email reset is unavailable; codes are never displayed in the interface or logs.

SMTP failures are logged without credentials and invalidate the affected code. The generic response does not guarantee delivery. Check host logs and your provider's delivery dashboard if email does not arrive. Delivery uses in-process background tasks, so an interruption during sending requires requesting another code; this is not a durable mail queue.

## Deploy as a website

For Render Free, follow the cloud PostgreSQL and HTTPS email instructions above. For a local SQLite deployment, choose a Python/container host with persistent disk, outbound SMTP, and an HTTPS endpoint. A static-only host cannot run this backend. Hosting account, public domain, sender address, and SMTP credentials are still needed; the project has not been published to an external host.

1. Deploy this folder using the included Dockerfile, or install `requirements.lock.txt` on a Python host.
2. Attach a persistent disk and set `NEXO_DATA_DIR` to its writable mount directory. For Docker, mount a volume at `/app/data`, writable by user ID 10001. Keep one application instance attached to this SQLite disk; do not horizontally scale across independent filesystems.
3. Set `NEXO_HTTPS=1`, `NEXO_ALLOWED_HOSTS=your-domain.example`, and `NEXO_PUBLIC_ORIGIN=https://your-domain.example` (no trailing slash). List multiple trusted hostnames separated by commas if required. Do not use a wildcard. Include the host's health-check hostname if it requires one.
4. Set the SMTP variables privately. Allow outbound SMTP to the provider. Keep port 8000 behind the host's HTTPS reverse proxy. Forward the public Host header; the configured public origin supports TLS termination.
5. For a native Python host, start `python -m uvicorn server:app --host 0.0.0.0 --port 8000 --no-proxy-headers` (replace 8000 with the host-assigned port). The Docker start command uses `PORT`, defaulting to 8000.
6. Configure a GET `/healthz` readiness check, automatic restarts, and encrypted backups of the persistent disk. Restore a backup in a separate environment before relying on it.
7. In the deployed HTTPS site, create two test accounts, verify login after closing/reopening the browser, test actual email delivery and password reset, check theme retention and account isolation, then remove the test accounts/data using your administration process.

The backend supports PostgreSQL using DATABASE_URL and otherwise uses local SQLite. The server ignores forwarded client IP headers by default to avoid spoofing. Behind a shared reverse proxy, its IP rate limit may be shared by visitors. Configure additional rate limiting at the trusted edge for a public service; only enable forwarded-IP processing when the proxy's trusted network addresses are known. Application limits persist in SQLite: 60 authentication requests per IP per 15 minutes and 10 login attempts per email per 15 minutes (including successful logins).

## Security and privacy

- Passwords use salted PBKDF2-HMAC-SHA256 with 600,000 iterations. Existing 300,000-iteration hashes upgrade on successful login. Passwords are never stored in plaintext.
- Session tokens are random; only their SHA-256 digests are stored. Cookies are HttpOnly, SameSite=Strict, and Secure when `NEXO_HTTPS=1`.
- Reset codes are salted and hashed, never returned from an API. Password reset atomically consumes the code and revokes the account's sessions. Legacy permanent recovery codes are no longer accepted.
- Habit operations, history, analytics, reports, and backup/restore check the authenticated user. Restoring a backup assigns ownership to that account, ignoring embedded user IDs.
- Private API responses use `Cache-Control: no-store`. The PWA worker caches only public static files. Cross-site writes and untrusted hosts are blocked; security headers restrict framing and scripts.
- The SQLite database contains personal data and hashed secrets. It is outside the public static directory but is not encrypted by the application. Restrict filesystem access, use encrypted host storage/backups, and HTTPS. Server administrators can access stored data. Reports and JSON downloads are private files that users must keep safe.
- Existing habit management, calendar, analytics, PDF/XLSX reports, JSON backups, browser reminders, and PWA installation remain available. Browser reminders require the page to stay open. This is an online app; private data is not cached for offline use.

## Existing accounts

Back up the old database while the server is stopped. Set `NEXO_DATA_DIR` to the existing data folder before launching the updated server. New tables are added without deleting accounts or habits. Existing logins remain valid until expiration or revocation. The old permanent recovery code is intentionally disabled; use the account's email inbox for recovery.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
node --check static/app.js
```

Tests cover the existing habit/report workflow, account isolation, persistent sessions, cookie flags, logout, password migration, email code generation with mocked delivery, expiry, guess limits, single-use concurrent redemption, session revocation, failed SMTP delivery, themes, request-origin protection, host validation, and rate limits. Real mailbox delivery requires your configured SMTP account. Both SQLite and a separate local PostgreSQL instance have been tested. Docker deployment, real cloud accounts, actual email delivery, and external HTTPS are not exercised by local tests.

Password reset design follows OWASP's guidance: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
