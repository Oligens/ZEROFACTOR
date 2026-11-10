# ZEROFACTOR dashboard and local API

## Start
Requirements: Python 3.11+.

```bash
python3 server/app.py
```

Open `http://127.0.0.1:8765/`. The server serves the dashboard and same-origin API. The default database is `zerofactor.sqlite3`; set `ZEROFACTOR_DB` to choose another SQLite path.

## Identity and project authorization
- Registration requires a valid-looking email and a password of at least 12 characters.
- Passwords are stored with scrypt and random per-user salts.
- Login issues opaque random session cookies; only a SHA-256 digest of the session token is stored.
- Session cookie is HttpOnly and SameSite=Strict; state-changing requests require a CSRF cookie/header match.
- Each project has an explicit membership. Queries are scoped to the authenticated user's membership; inaccessible project IDs return 404.
- Owner can delete the project and add existing registered users as Analysts or Viewers.
- Owner and Analyst can add assessments; Viewer is read-only.

## API
- POST /api/register
- POST /api/login
- POST /api/logout
- GET /api/me
- GET /api/projects; POST /api/projects
- GET /api/projects/{id}; DELETE /api/projects/{id}
- POST /api/projects/{id}/assessments
- POST /api/projects/{id}/members

The browser dashboard imports JSON reports into the selected server-side project and loads assessment history from SQLite. It no longer relies on localStorage role selectors.

## Deployment boundary
This is a local development backend, not a production internet-facing service. It binds to loopback only. It does not yet include email verification, password reset, MFA, login rate limiting, session rotation/revocation UI, secure reverse-proxy/TLS deployment, encrypted database-at-rest key management, signed audit logs, backup/restore, invitation workflow or production observability. Do not expose it publicly until those controls and an independent security review are complete.
