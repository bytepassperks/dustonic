// Local end-to-end check: boots the real server.js with a Dodo webhook secret
// set (but Mailgun unset, so no real email is sent), then drives the webhook
// with signed payloads and asserts issuance, dedupe, bad-signature rejection,
// revocation, and that existing routes still work. Run with: node test/dodo.integration.mjs
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const PORT = 4567;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = "whsec_" + Buffer.from("integration-secret").toString("base64");
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "dodo-int-"));

const env = {
  ...process.env,
  PORT: String(PORT),
  DATA_DIR,
  SITE_URL: BASE,
  DODO_WEBHOOK_SECRET: SECRET,
  DODO_PRO_PRODUCT_IDS: "prod_pro_m,prod_pro_y",
  DODO_CHECKOUT_PRO_MONTHLY: "https://checkout.dodopayments.com/pro-m",
  // Ensure no real mail is attempted.
  MAILGUN_API_KEY: "",
  MAILGUN_DOMAIN: "",
};

function sign(id, ts, body) {
  const key = Buffer.from(SECRET.slice(6), "base64");
  return "v1," + crypto.createHmac("sha256", key).update(`${id}.${ts}.${body}`).digest("base64");
}

async function postWebhook(id, event, { tamper = false } = {}) {
  const ts = Math.floor(Date.now() / 1000).toString();
  const body = JSON.stringify(event);
  const sig = sign(id, ts, tamper ? body + "x" : body);
  const res = await fetch(`${BASE}/api/dodo/webhook`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "webhook-id": id,
      "webhook-timestamp": ts,
      "webhook-signature": sig,
    },
    body,
  });
  let json = null;
  try {
    json = await res.json();
  } catch {
    /* non-JSON */
  }
  return { status: res.status, json };
}

let failures = 0;
function check(label, cond, extra) {
  const ok = Boolean(cond);
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${extra ? `  ${JSON.stringify(extra)}` : ""}`);
}

async function waitForHealth() {
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`${BASE}/healthz`);
      if (r.ok) return true;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

const server = spawn("node", ["server.js"], {
  cwd: path.resolve(import.meta.dirname, ".."),
  env,
  stdio: ["ignore", "pipe", "pipe"],
});
server.stdout.on("data", (d) => process.stdout.write(`[srv] ${d}`));
server.stderr.on("data", (d) => process.stderr.write(`[srv] ${d}`));

try {
  if (!(await waitForHealth())) throw new Error("server did not become healthy");

  // 1. Valid one-time Pro payment → license issued.
  const payEvent = {
    type: "payment.succeeded",
    data: {
      payment_id: "pay_int_1",
      customer: { customer_id: "cus_1", email: "buyer@example.com", name: "Buyer" },
      product_cart: [{ product_id: "prod_pro_m", quantity: 1 }],
    },
  };
  const r1 = await postWebhook("evt_int_1", payEvent);
  check("payment.succeeded issues a license", r1.status === 200 && r1.json?.issued, r1.json);
  check("issued license is pro tier", r1.json?.tier === "pro");
  const key = r1.json?.issued;

  // 2. Replay same event id → deduped at the event layer.
  const r2 = await postWebhook("evt_int_1", payEvent);
  check("replayed event id is deduped", r2.status === 200 && r2.json?.deduped === true, r2.json);

  // 3. Different event id, same payment → business-level dedupe (no new license).
  const r3 = await postWebhook("evt_int_1b", payEvent);
  check("same payment via new event id is deduped", r3.json?.deduped === key, r3.json);

  // 4. Bad signature → 401.
  const r4 = await postWebhook("evt_int_bad", payEvent, { tamper: true });
  check("tampered signature rejected (401)", r4.status === 401, r4.json);

  // 5. Issued key validates via the desktop-app endpoint (unchanged route).
  const v = await fetch(`${BASE}/api/license/validate`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ key }),
  });
  const vj = await v.json();
  check("issued key validates as pro", v.status === 200 && vj.valid === true && vj.tier === "pro", vj);

  // 6. Refund for that payment → license revoked.
  const refundEvent = {
    type: "refund.succeeded",
    data: { payment_id: "pay_int_1", customer: { email: "buyer@example.com" } },
  };
  const r6 = await postWebhook("evt_int_refund", refundEvent);
  check("refund revokes the license", r6.json?.revoked === key, r6.json);

  // 7. Revoked key no longer validates.
  const v2 = await fetch(`${BASE}/api/license/validate`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ key }),
  });
  const vj2 = await v2.json();
  check("revoked key no longer validates", vj2.valid === false, vj2);

  // 9. Public config endpoint reports enabled + only configured links.
  const cfg = await (await fetch(`${BASE}/api/dodo/config`)).json();
  check("config endpoint reports enabled with pro-monthly link", cfg.enabled === true && !!cfg.links.proMonthly && !cfg.links.proAnnual, cfg);

  // 10. Existing routes intact.
  const health = await fetch(`${BASE}/healthz`);
  const home = await fetch(`${BASE}/`);
  check("healthz + home still 200", health.status === 200 && home.status === 200);
} catch (err) {
  failures++;
  console.error("ERROR", err);
} finally {
  server.kill("SIGTERM");
  fs.rmSync(DATA_DIR, { recursive: true, force: true });
  console.log(failures === 0 ? "\nALL INTEGRATION CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}
