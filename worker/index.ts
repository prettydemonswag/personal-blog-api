const encoder = new TextEncoder();
const TOKEN_LIFETIME_SECONDS = 12 * 60 * 60;
const MAX_BODY_LENGTH = 100000;

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");
    const allowedOrigins = (env.ALLOWED_ORIGIN || "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);

    if (origin && !allowedOrigins.includes(origin)) {
      return json({ error: "This website is not allowed to use the blog API." }, 403);
    }

    const cors = corsHeaders(origin, allowedOrigins);
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    try {
      if (path === "/api/health" && request.method === "GET") {
        return json({ ok: true }, 200, cors);
      }

      if (path === "/api/entries" && request.method === "GET") {
        const result = await env.DB.prepare(
          "SELECT id, title, body, entry_date, created_at, updated_at FROM entries ORDER BY entry_date DESC, id DESC"
        ).all();
        return json({ entries: result.results || [] }, 200, cors);
      }

      if (path === "/api/login" && request.method === "POST") {
        const body = await readJson(request);
        if (!body || typeof body.password !== "string") {
          return json({ error: "Enter the passcode." }, 400, cors);
        }
        if (!env.BLOG_PASSWORD || body.password !== env.BLOG_PASSWORD) {
          return json({ error: "That passcode is incorrect." }, 401, cors);
        }
        if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32) {
          return json({ error: "The Worker needs a SESSION_SECRET of at least 32 characters." }, 500, cors);
        }
        const token = await createToken(env.SESSION_SECRET);
        return json({ token }, 200, cors);
      }

      if (path === "/api/entries" && request.method === "POST") {
        if (!(await authorized(request, env))) return json({ error: "Your editor session expired. Unlock the editor again." }, 401, cors);
        const body = await readJson(request);
        const validated = validateEntry(body);
        if (validated.error) return json({ error: validated.error }, 400, cors);

        const now = new Date().toISOString();
        const result = await env.DB.prepare(
          "INSERT INTO entries (title, body, entry_date, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
        ).bind(validated.title, validated.body, validated.entryDate, now, now).run();

        const entry = await env.DB.prepare(
          "SELECT id, title, body, entry_date, created_at, updated_at FROM entries WHERE id = ?"
        ).bind(result.meta.last_row_id).first();
        return json({ entry }, 201, cors);
      }

      const match = path.match(/^\/api\/entries\/(\d+)$/);
      if (match && request.method === "PUT") {
        if (!(await authorized(request, env))) return json({ error: "Your editor session expired. Unlock the editor again." }, 401, cors);
        const body = await readJson(request);
        const validated = validateEntry(body);
        if (validated.error) return json({ error: validated.error }, 400, cors);

        const now = new Date().toISOString();
        const result = await env.DB.prepare(
          "UPDATE entries SET title = ?, body = ?, entry_date = ?, updated_at = ? WHERE id = ?"
        ).bind(validated.title, validated.body, validated.entryDate, now, Number(match[1])).run();

        if (!result.meta.changes) return json({ error: "Entry not found." }, 404, cors);
        const entry = await env.DB.prepare(
          "SELECT id, title, body, entry_date, created_at, updated_at FROM entries WHERE id = ?"
        ).bind(Number(match[1])).first();
        return json({ entry }, 200, cors);
      }

      if (match && request.method === "DELETE") {
        if (!(await authorized(request, env))) return json({ error: "Your editor session expired. Unlock the editor again." }, 401, cors);
        const result = await env.DB.prepare("DELETE FROM entries WHERE id = ?")
          .bind(Number(match[1])).run();
        if (!result.meta.changes) return json({ error: "Entry not found." }, 404, cors);
        return json({ ok: true }, 200, cors);
      }

      return json({ error: "Not found." }, 404, cors);
    } catch (error) {
      return json({ error: error instanceof Error ? error.message : "Unexpected server error." }, 500, cors);
    }
  }
};

function corsHeaders(origin, allowedOrigins) {
  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
  if (origin && allowedOrigins.includes(origin)) headers["Access-Control-Allow-Origin"] = origin;
  return headers;
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extraHeaders }
  });
}

async function readJson(request) {
  const text = await request.text();
  if (text.length > MAX_BODY_LENGTH + 10000) throw new Error("Request is too large.");
  try { return JSON.parse(text); }
  catch (_) { return null; }
}

function validateEntry(body) {
  if (!body || typeof body !== "object") return { error: "Entry data is missing or invalid." };
  const title = typeof body.title === "string" ? body.title.trim() : "";
  const text = typeof body.body === "string" ? body.body : "";
  const entryDate = typeof body.entryDate === "string" ? body.entryDate.trim() : "";

  if (!text.trim()) return { error: "An entry cannot be empty." };
  if (text.length > MAX_BODY_LENGTH) return { error: "Entries must be 100,000 characters or fewer." };
  if (title.length > 200) return { error: "Titles must be 200 characters or fewer." };
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(entryDate) || Number.isNaN(Date.parse(entryDate))) {
    return { error: "Choose a valid date and time." };
  }
  return { title, body: text, entryDate };
}

async function createToken(secret) {
  const exp = Math.floor(Date.now() / 1000) + TOKEN_LIFETIME_SECONDS;
  const payload = base64url(encoder.encode(JSON.stringify({ exp })));
  const signature = await sign(payload, secret);
  return `${payload}.${signature}`;
}

async function authorized(request, env) {
  const header = request.headers.get("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token || !env.SESSION_SECRET) return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const expected = await sign(parts[0], env.SESSION_SECRET);
  if (!constantTimeEqual(parts[1], expected)) return false;

  try {
    const payloadText = new TextDecoder().decode(fromBase64url(parts[0]));
    const payload = JSON.parse(payloadText);
    return Number.isFinite(payload.exp) && payload.exp > Math.floor(Date.now() / 1000);
  } catch (_) {
    return false;
  }
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return base64url(new Uint8Array(signature));
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(base64);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
