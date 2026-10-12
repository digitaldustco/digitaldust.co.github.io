const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const TEST_TABLE_SQL = "CREATE TABLE IF NOT EXISTS dust_tracking_test (code TEXT PRIMARY KEY, stripe_session_id TEXT NOT NULL UNIQUE, started_at TEXT NOT NULL)";

function json(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "access-control-allow-origin": origin || "", "access-control-allow-methods": "GET, OPTIONS", vary: "Origin" },
  });
}
function originFor(request, env) {
  const origin = request.headers.get("Origin") || "";
  return origin === env.ALLOWED_ORIGIN ? origin : "";
}
function hex(buffer) {
  return [...new Uint8Array(buffer)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
async function validSignature(body, header, secret) {
  if (!header || !secret) return false;
  const parts = header.split(",").map((part) => part.split("=", 2));
  const timestamp = parts.find(([key]) => key === "t")?.[1];
  const signatures = parts.filter(([key]) => key === "v1").map(([, value]) => value);
  if (!timestamp || Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signed = timestamp + "." + body;
  const expected = hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signed)));
  return signatures.some((signature) => signature === expected);
}
function newCode() {
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  return "DUST-Tracking-" + [...bytes].map((byte) => ALPHABET[byte % ALPHABET.length]).join("");
}
async function webhook(request, env) {
  const body = await request.text();
  let event;
  try { event = JSON.parse(body); } catch { return new Response("Invalid JSON", { status: 400 }); }
  const isTest = event.livemode === false;
  const secret = isTest ? env.STRIPE_TEST_WEBHOOK_SECRET : env.STRIPE_WEBHOOK_SECRET;
  if (!(await validSignature(body, request.headers.get("Stripe-Signature"), secret))) return new Response("Invalid signature", { status: 400 });
  if (["checkout.session.completed", "checkout.session.async_payment_succeeded"].includes(event.type)) {
    const session = event.data?.object;
    const expectedLink = isTest ? env.STRIPE_TEST_PAYMENT_LINK_ID : env.STRIPE_PAYMENT_LINK_ID;
    if (session?.payment_status === "paid" && session.mode === "payment" && session.payment_link === expectedLink && session.currency === "gbp" && session.amount_total === 100 && session.id) {
      const table = isTest ? "dust_tracking_test" : "dust_tracking";
      if (isTest) await env.TRACKING_DB.prepare(TEST_TABLE_SQL).run();
      let record = await env.TRACKING_DB.prepare("SELECT code FROM " + table + " WHERE stripe_session_id = ?").bind(session.id).first();
      if (!record) {
        await env.TRACKING_DB.prepare("INSERT OR IGNORE INTO " + table + " (code, stripe_session_id, started_at) VALUES (?, ?, ?)").bind(newCode(), session.id, new Date(event.created * 1000).toISOString()).run();
        record = await env.TRACKING_DB.prepare("SELECT code FROM " + table + " WHERE stripe_session_id = ?").bind(session.id).first();
      }
    }
  }
  return Response.json({ received: true });
}
async function findByCode(database, code) {
  let record = await database.prepare("SELECT code, started_at AS startedAt FROM dust_tracking WHERE code = ?").bind(code).first();
  if (!record) {
    await database.prepare(TEST_TABLE_SQL).run();
    record = await database.prepare("SELECT code, started_at AS startedAt FROM dust_tracking_test WHERE code = ?").bind(code).first();
  }
  return record;
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/webhook" && request.method === "POST") return webhook(request, env);
    const origin = originFor(request, env);
    if (request.method === "OPTIONS") return new Response(null, { status: origin ? 204 : 403, headers: { "access-control-allow-origin": origin, "access-control-allow-methods": "GET, OPTIONS", "access-control-max-age": "86400" } });
    if (request.method !== "GET" || !origin) return json({ error: "Not found" }, 404, origin);
    let record;
    if (url.pathname === "/api/track") {
      const input = (url.searchParams.get("code") || "").trim().toUpperCase();
      if (!/^DUST-TRACKING-[A-HJ-NP-Z2-9]{10}$/.test(input)) return json({ error: "We could not find that tracking code. Check it and try again." }, 404, origin);
      record = await findByCode(env.TRACKING_DB, "DUST-Tracking-" + input.slice(14));
    } else if (url.pathname === "/api/receipt") {
      const sessionId = url.searchParams.get("session_id") || "";
      if (!/^cs_(live|test)_[A-Za-z0-9]+$/.test(sessionId)) return json({ error: "Receipt not found" }, 404, origin);
      const table = sessionId.startsWith("cs_test_") ? "dust_tracking_test" : "dust_tracking";
      if (table === "dust_tracking_test") await env.TRACKING_DB.prepare(TEST_TABLE_SQL).run();
      record = await env.TRACKING_DB.prepare("SELECT code, started_at AS startedAt FROM " + table + " WHERE stripe_session_id = ?").bind(sessionId).first();
    } else return json({ error: "Not found" }, 404, origin);
    return record ? json(record, 200, origin) : json({ error: "Not found" }, 404, origin);
  },
};
