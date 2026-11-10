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


## Isolated Neon database for pull requests

The workflow `.github/workflows/neon-preview-branches.yml` provisions one Neon branch per same-repository pull request:

- Branch name: `preview-pr-<PR number>`, derived from the protected Neon `main` branch.
- Database and role: `zerofactor` / `zerofactor_owner`.
- Expiration: 14 days.
- The idempotent schema migration is applied to that branch, then the workflow verifies that all five required tables exist and that PostgreSQL responds.
- Closing the pull request deletes only its `preview-pr-<PR number>` branch. Neon `main` is never a cleanup target.
- Fork pull requests are intentionally skipped because repository secrets are not exposed to untrusted fork code.

### Required GitHub Actions configuration

Configure these repository-level values before expecting the workflow to pass:

- Actions variable `NEON_PROJECT_ID`: the dedicated ZEROFACTOR Neon project ID.
- Actions secret `NEON_API_KEY`: a Neon API key with permission to create and delete branches in that project.

Do not put the API key in repository files, workflow output, or issue comments. The workflow never prints the generated database URL.

### Important Vercel Preview boundary

This workflow creates and validates an isolated database for CI. It does not automatically rewrite Vercel environment variables or route a Vercel deployment to the ephemeral branch. The existing Vercel `DATABASE_URL` remains scoped to the repair Preview branch; Production variables and deployments are unchanged. Wiring each ephemeral Neon URL into Vercel would additionally require a dedicated, least-privilege Vercel token stored as a GitHub Actions secret and a carefully scoped Preview-only environment-variable lifecycle. Do not add that token or broaden the environment scope without a separate review.
