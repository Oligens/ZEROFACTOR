# ZEROFACTOR local platform API

The first server-backed milestone is deliberately local-only. Start with Python 3.11+:

```bash
python3 server/app.py
python3 -m unittest discover -s server -p 'test_*.py'
```

API: `http://127.0.0.1:8765`. SQLite is stored at `ZEROFACTOR_DB` (default `zerofactor.sqlite3`). Passwords use scrypt; session identifiers are random opaque tokens stored only as SHA-256 hashes; session cookies are HttpOnly and SameSite=Strict; mutating authenticated requests require the CSRF cookie value in `X-CSRF-Token`. All project and assessment queries are membership-scoped. Roles: owner, analyst, viewer.

Endpoints: POST /api/register, POST /api/login, POST /api/logout, GET/POST /api/projects, GET/DELETE /api/projects/{id}, POST /api/projects/{id}/assessments, POST /api/projects/{id}/members. Project membership is not global; unauthorized projects return 404.

**Deployment boundary:** this is a local development backend, not a production internet-facing service. It binds loopback only, has no email verification, password reset, MFA, rate limiting, reverse-proxy/TLS configuration, key rotation, audit log signing, backup/restore or hardened operational deployment. Do not expose it publicly until these are implemented and independently reviewed. Registration is open on the local instance.
