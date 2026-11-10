# Vercel deployment and persistent backend

The public dashboard is served from the \`dashboard/\` output directory. The API is a Node.js Vercel Function in \`api/[...path].js\`; it does not start a long-running WSGI server.

## Persistent storage

Production API data is stored in Neon PostgreSQL using the \`DATABASE_URL\` environment variable. Use a pooled Neon connection string for serverless traffic. The local-only \`server/app.py\` SQLite server remains available for local development and is not the Vercel production backend.

Apply \`migrations/001_vercel_backend.sql\` to the dedicated ZEROFACTOR database before enabling the function. Never point this application at another project's database.

## Vercel environment

Add \`DATABASE_URL\` as an encrypted/sensitive environment variable for Preview first. Restrict it to the repair branch while testing. Do not set it for Production until the preview has passed acceptance tests and the owner approves the production change.

The API requires HTTPS cookies and same-origin requests. It preserves the existing endpoints:
- POST /api/register
- POST /api/login
- POST /api/logout
- GET /api/health
- GET /api/me
- GET/POST /api/projects
- GET/DELETE /api/projects/{id}
- POST /api/projects/{id}/assessments
- POST /api/projects/{id}/members

Passwords use scrypt, session identifiers are stored as SHA-256 hashes, sessions expire after eight hours, writes require the CSRF token, and project membership/roles are checked server-side.

## Preview acceptance

1. GET /api/health returns \`{"status":"ok","storage":"postgresql","provider":"neon"}\`.
2. Register a test account, log in, create a project, and reload.
3. Upload a JSON report and confirm it remains in the project history after another request.
4. Create a second account, add it as Viewer, and confirm it can read but cannot upload or delete.
5. Confirm unauthenticated users cannot access projects.
6. Confirm Production still points to the existing deployment until explicit approval.

The API returns generic errors to clients and writes diagnostic details to Vercel runtime logs without logging passwords or session tokens.
