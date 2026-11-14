# Verification results

- SQLite backend: **17 passed**, 28.35 seconds.
- PostgreSQL 18 backend: **17 passed**, 43.84 seconds, using a separate loopback-only test database.
- Python 3.14.2 on Windows; PostgreSQL tested using psycopg's supported pure-Python implementation and the installed PostgreSQL library. The downloaded Windows binary driver was blocked by application control; no security policy was changed. The Linux deployment uses the packaged binary driver.
- One upstream Starlette TestClient deprecation warning in each run.
- JavaScript and Python syntax checks passed.
- Original style.css remains unchanged.

Tests cover habit/report workflows, account isolation, themes, persistent sessions, cookie flags, logout, password migration, reset-code hashing/expiry/guess limits/concurrent single-use, session revocation, SMTP transport mocks, Brevo HTTPS API mocks, TLS configuration, host/origin restrictions, health checks, and refusal to use temporary SQLite storage on Render.

No real cloud database, real inbox delivery, Render deployment, Docker build, or browser visual verification has been performed. Complete those checks with your private configuration before sharing the deployed app.

No passwords, API keys, databases, virtual environments, or test data are included in the upload folder.
