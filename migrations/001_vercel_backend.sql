-- ZEROFACTOR persistent backend schema (PostgreSQL / Neon)
-- Apply once to the dedicated ZEROFACTOR database before deploying the API.
CREATE TABLE IF NOT EXISTS users (
  id text PRIMARY KEY,
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  created_at bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS projects (
  id text PRIMARY KEY,
  name text NOT NULL,
  created_by text NOT NULL REFERENCES users(id),
  created_at bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('owner','analyst','viewer')),
  PRIMARY KEY (project_id,user_id)
);
CREATE INDEX IF NOT EXISTS memberships_user_id_idx ON memberships(user_id);
CREATE TABLE IF NOT EXISTS assessments (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  label text NOT NULL,
  report_json jsonb NOT NULL,
  created_at bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS assessments_project_created_idx ON assessments(project_id,created_at DESC);
