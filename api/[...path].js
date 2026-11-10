const crypto = require("node:crypto");
const { Pool } = require("pg");

const SESSION_SECONDS = 8 * 60 * 60;
const MAX_BODY_BYTES = 1_000_000;
const COOKIE_SECURE = true;

let pool;
function db() {
  if (!process.env.DATABASE_URL) {
    const error = new Error("DATABASE_URL is not configured");
    error.statusCode = 503;
    throw error;
  }
  if (!pool) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 1,
      idleTimeoutMillis: 10000,
      connectionTimeoutMillis: 7000,
      allowExitOnIdle: true
    });
    pool.on("error", (error) => console.error("ZEROFACTOR database pool error", error));
  }
  return pool;
}

function send(res, status, payload, extraHeaders = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  for (const [key, value] of Object.entries(extraHeaders)) res.setHeader(key, value);
  res.end(JSON.stringify(payload));
}

function cookies(req) {
  const raw = req.headers.cookie || "";
  const result = {};
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    try { result[key] = decodeURIComponent(value); } catch { result[key] = value; }
  }
  return result;
}

function cookie(name, value, options = {}) {
  const parts = [name + "=" + encodeURIComponent(value), "Path=/", "SameSite=Strict"];
  if (options.httpOnly) parts.push("HttpOnly");
  if (COOKIE_SECURE) parts.push("Secure");
  if (options.maxAge !== undefined) parts.push("Max-Age=" + options.maxAge);
  return parts.join("; ");
}

function parseBody(req) {
  let body = req.body;
  if (body === undefined || body === null || body === "") return {};
  if (Buffer.isBuffer(body)) body = body.toString("utf8");
  if (typeof body === "string") {
    if (Buffer.byteLength(body) > MAX_BODY_BYTES) {
      const error = new Error("body_too_large"); error.statusCode = 413; throw error;
    }
    try { body = JSON.parse(body); } catch {
      const error = new Error("invalid_json_or_request"); error.statusCode = 400; throw error;
    }
  } else if (Buffer.byteLength(JSON.stringify(body)) > MAX_BODY_BYTES) {
    const error = new Error("body_too_large"); error.statusCode = 413; throw error;
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    const error = new Error("json_object_required"); error.statusCode = 400; throw error;
  }
  return body;
}

function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function passwordHash(password) {
  const salt = crypto.randomBytes(16);
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 32, { N: 16384, r: 8, p: 1 }, (error, key) => {
      if (error) return reject(error);
      resolve(Buffer.concat([salt, key]).toString("base64"));
    });
  });
}

function passwordOk(password, stored) {
  let raw;
  try { raw = Buffer.from(stored, "base64"); } catch { return Promise.resolve(false); }
  if (raw.length !== 48) return Promise.resolve(false);
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, raw.subarray(0, 16), 32, { N: 16384, r: 8, p: 1 }, (error, key) => {
      if (error) return reject(error);
      resolve(crypto.timingSafeEqual(key, raw.subarray(16)));
    });
  });
}

async function currentUser(req, client) {
  const token = cookies(req).zf_session;
  if (!token) return null;
  const result = await client.query(
    "SELECT u.id, u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>$2",
    [hash(token), Math.floor(Date.now() / 1000)]
  );
  return result.rows[0] || null;
}

function requireCsrf(req) {
  const jar = cookies(req);
  const supplied = req.headers["x-csrf-token"];
  if (!jar.zf_csrf || typeof supplied !== "string" ||
      Buffer.byteLength(jar.zf_csrf) !== Buffer.byteLength(supplied) ||
      !crypto.timingSafeEqual(Buffer.from(jar.zf_csrf), Buffer.from(supplied))) {
    const error = new Error("csrf_validation_failed"); error.statusCode = 403; throw error;
  }
}

function id() { return crypto.randomBytes(16).toString("hex"); }

async function handler(req, res) {
  const pathname = new URL(req.url, "https://zerofactor.invalid").pathname.replace(/\/+$/, "") || "/";
  const method = (req.method || "GET").toUpperCase();
  const body = parseBody(req);
  const pool = db();

  if (pathname === "/api/health" && method === "GET") {
    await pool.query("SELECT 1");
    return send(res, 200, { status: "ok", storage: "postgresql", provider: "neon" });
  }

  const publicAuth = pathname === "/api/register" || pathname === "/api/login";
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method) && !publicAuth) requireCsrf(req);

  if (pathname === "/api/register" && method === "POST") {
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || password.length < 12 || password.length > 256) {
      return send(res, 400, { error: "valid_email_and_12_char_password_required" });
    }
    const uid = id();
    try {
      await pool.query("INSERT INTO users(id,email,password_hash,created_at) VALUES($1,$2,$3,$4)",
        [uid, email, await passwordHash(password), Math.floor(Date.now() / 1000)]);
    } catch (error) {
      if (error.code === "23505") return send(res, 409, { error: "email_already_registered" });
      throw error;
    }
    return send(res, 201, { user: { id: uid, email } });
  }

  if (pathname === "/api/login" && method === "POST") {
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const result = await pool.query("SELECT id,email,password_hash FROM users WHERE email=$1", [email]);
    const user = result.rows[0];
    if (!user || !(await passwordOk(password, user.password_hash))) {
      return send(res, 401, { error: "invalid_credentials" });
    }
    const rawToken = crypto.randomBytes(32).toString("base64url");
    const csrfToken = crypto.randomBytes(24).toString("base64url");
    const now = Math.floor(Date.now() / 1000);
    await pool.query("DELETE FROM sessions WHERE expires_at <= $1", [now]);
    await pool.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)",
      [hash(rawToken), user.id, now + SESSION_SECONDS]);
    return send(res, 200, { user: { id: user.id, email: user.email }, csrf_token: csrfToken }, {
      "Set-Cookie": [
        cookie("zf_session", rawToken, { httpOnly: true, maxAge: SESSION_SECONDS }),
        cookie("zf_csrf", csrfToken, { maxAge: SESSION_SECONDS })
      ]
    });
  }

  const client = await pool.connect();
  try {
    if (pathname === "/api/logout" && method === "POST") {
      const token = cookies(req).zf_session;
      if (token) await client.query("DELETE FROM sessions WHERE token_hash=$1", [hash(token)]);
      return send(res, 200, { logged_out: true }, {
        "Set-Cookie": [
          cookie("zf_session", "", { httpOnly: true, maxAge: 0 }),
          cookie("zf_csrf", "", { maxAge: 0 })
        ]
      });
    }

    const user = await currentUser(req, client);
    if (!user) return send(res, 401, { error: "authentication_required" });

    if (pathname === "/api/me" && method === "GET") {
      return send(res, 200, { user });
    }

    if (pathname === "/api/projects" && method === "GET") {
      const result = await client.query(
        "SELECT p.id,p.name,p.created_at,m.role FROM projects p JOIN memberships m ON m.project_id=p.id WHERE m.user_id=$1 ORDER BY p.created_at DESC",
        [user.id]
      );
      return send(res, 200, { projects: result.rows });
    }

    if (pathname === "/api/projects" && method === "POST") {
      const name = String(body.name || "").trim();
      if (!name || name.length > 120) return send(res, 400, { error: "project_name_required_max_120" });
      const projectId = id();
      const now = Math.floor(Date.now() / 1000);
      await client.query("BEGIN");
      try {
        await client.query("INSERT INTO projects(id,name,created_by,created_at) VALUES($1,$2,$3,$4)", [projectId, name, user.id, now]);
        await client.query("INSERT INTO memberships(project_id,user_id,role) VALUES($1,$2,'owner')", [projectId, user.id]);
        await client.query("COMMIT");
      } catch (error) { await client.query("ROLLBACK"); throw error; }
      return send(res, 201, { id: projectId, name, role: "owner" });
    }

    const parts = pathname.split("/").filter(Boolean);
    if (parts.length >= 3 && parts[0] === "api" && parts[1] === "projects") {
      const projectId = parts[2];
      const membership = await client.query(
        "SELECT role FROM memberships WHERE project_id=$1 AND user_id=$2", [projectId, user.id]
      );
      if (!membership.rows.length) return send(res, 404, { error: "project_not_found" });
      const role = membership.rows[0].role;

      if (parts.length === 3 && method === "GET") {
        const project = await client.query("SELECT id,name,created_at FROM projects WHERE id=$1", [projectId]);
        const assessments = await client.query(
          "SELECT id,label,created_at,report_json AS report FROM assessments WHERE project_id=$1 ORDER BY created_at DESC",
          [projectId]
        );
        return send(res, 200, { project: project.rows[0], assessments: assessments.rows });
      }

      if (parts.length === 3 && method === "DELETE") {
        if (role !== "owner") return send(res, 403, { error: "owner_role_required" });
        await client.query("DELETE FROM projects WHERE id=$1", [projectId]);
        return send(res, 200, { deleted: true });
      }

      if (parts.length === 4 && parts[3] === "assessments" && method === "POST") {
        if (!["owner", "analyst"].includes(role)) return send(res, 403, { error: "analyst_or_owner_required" });
        if (!body.report || typeof body.report !== "object" || Array.isArray(body.report)) {
          return send(res, 400, { error: "report_object_required" });
        }
        const assessmentId = id();
        const label = String(body.label || "Assessment").slice(0, 160);
        await client.query(
          "INSERT INTO assessments(id,project_id,label,report_json,created_at) VALUES($1,$2,$3,$4::jsonb,$5)",
          [assessmentId, projectId, label, JSON.stringify(body.report), Math.floor(Date.now() / 1000)]
        );
        return send(res, 201, { id: assessmentId, label });
      }

      if (parts.length === 4 && parts[3] === "members" && method === "POST") {
        if (role !== "owner") return send(res, 403, { error: "owner_role_required" });
        const email = String(body.email || "").trim().toLowerCase();
        const newRole = body.role;
        if (!["analyst", "viewer"].includes(newRole)) {
          return send(res, 400, { error: "existing_user_and_analyst_or_viewer_role_required" });
        }
        const target = await client.query("SELECT id FROM users WHERE email=$1", [email]);
        if (!target.rows.length) return send(res, 400, { error: "existing_user_and_analyst_or_viewer_role_required" });
        await client.query(
          "INSERT INTO memberships(project_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT(project_id,user_id) DO UPDATE SET role=EXCLUDED.role",
          [projectId, target.rows[0].id, newRole]
        );
        return send(res, 201, { project_id: projectId, role: newRole });
      }
    }

    return send(res, 404, { error: "not_found" });
  } finally {
    client.release();
  }
}

module.exports = async function api(req, res) {
  try {
    await handler(req, res);
  } catch (error) {
    const requestId = req.headers["x-vercel-id"] || "unknown";
    if (error.statusCode) return send(res, error.statusCode, { error: error.message });
    console.error("ZEROFACTOR API invocation failed", { requestId, message: error.message, stack: error.stack });
    return send(res, 500, { error: "internal_error", request_id: requestId });
  }
};
