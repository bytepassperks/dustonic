// Server-rendered HTML for the admin panel. No template engine — small
// tagged helpers keep the markup readable and auto-escape interpolations.

// A string of already-safe HTML that must not be re-escaped.
class RawHtml {
  constructor(value) {
    this.value = value;
  }
  toString() {
    return this.value;
  }
}

function esc(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Render a value for interpolation: trusted HTML passes through, arrays are
// rendered element-by-element, everything else is escaped.
function render(value) {
  if (value == null || value === false) return "";
  if (value instanceof RawHtml) return value.value;
  if (Array.isArray(value)) return value.map(render).join("");
  return esc(value);
}

function html(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) {
    out += render(values[i]) + strings[i + 1];
  }
  return new RawHtml(out);
}

// Marks a pre-built HTML fragment (or array of them) as safe.
function raw(value) {
  if (value instanceof RawHtml) return value;
  return new RawHtml(render(value));
}

const STYLE = `
  :root{--ink:#08131f;--paper:#f4f8fb;--card:#fff;--line:#dce6ed;--pop:#0e5fd8;--muted:#607487;--ok:#087f73;--warn:#b4690e;--bad:#c0392b}
  *{box-sizing:border-box}
  body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;background:var(--paper);color:var(--ink);font-size:15px;line-height:1.5}
  a{color:var(--pop)}
  .wrap{max-width:1040px;margin:0 auto;padding:28px 22px 64px}
  header.bar{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:24px}
  .brand{font-weight:800;letter-spacing:-.02em;font-size:20px}
  .brand small{font-weight:600;color:var(--muted);margin-left:8px;font-size:12px;text-transform:uppercase;letter-spacing:.12em}
  h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:32px 0 12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
  .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:18px;box-shadow:0 1px 0 rgba(0,0,0,.02)}
  table{width:100%;border-collapse:collapse}
  th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}
  th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em}
  .pill.pending{background:#fff3df;color:var(--warn)} .pill.approved{background:#e4f7ec;color:var(--ok)} .pill.rejected{background:#fdecea;color:var(--bad)}
  .pill.active{background:#e4f7ec;color:var(--ok)} .pill.revoked{background:#f1eef6;color:var(--muted)}
  .pill.free{background:#eef0f4;color:#444} .pill.pro{background:#dff8f4;color:#087f73}
  input,select,button,textarea{font:inherit}
  input,select{padding:9px 11px;border:1px solid var(--line);border-radius:9px;background:#fff;color:var(--ink)}
  .btn{display:inline-block;padding:8px 14px;border-radius:9px;border:1px solid var(--line);background:#fff;color:var(--ink);font-weight:700;cursor:pointer;text-decoration:none;font-size:13px}
  .btn--pop{background:var(--pop);border-color:var(--pop);color:#fff}
  .btn--bad{color:var(--bad);border-color:#f0c8c2}
  .btn--ghost{background:transparent}
  form.inline{display:inline-flex;gap:6px;align-items:center;margin:0}
  .row-actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  .muted{color:var(--muted)} .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  .empty{color:var(--muted);padding:18px 8px}
  .msg{white-space:pre-wrap;max-width:380px;color:var(--muted)}
  .login{max-width:380px;margin:9vh auto 0}
  .login .card{padding:26px}
  .field{display:block;margin-bottom:14px}
  .field span{display:block;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:6px}
  .field input{width:100%}
  .note{background:#fff7e9;border:1px solid #f0e0bd;color:#7a5a12;border-radius:9px;padding:10px 12px;font-size:13px;margin-bottom:16px}
  .err{background:#fdecea;border:1px solid #f0c8c2;color:var(--bad);border-radius:9px;padding:10px 12px;font-size:13px;margin-bottom:16px}
`;

function page(title, bodyHtml) {
  return html`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="robots" content="noindex,nofollow"/>
<title>${title}</title>
<style>${raw(STYLE)}</style>
</head><body>${raw(bodyHtml)}</body></html>`.toString();
}

export function renderLogin({ error } = {}) {
  const body = html`<div class="wrap"><div class="login">
    <div class="brand">Dustonic <small>Admin</small></div>
    <div class="card">
      <h1>Sign in</h1>
      <p class="muted" style="margin-top:4px">Approve access requests and issue license keys.</p>
      ${error ? raw(html`<div class="err">${error}</div>`) : ""}
      <form method="post" action="/admin/login">
        <label class="field"><span>Email</span><input type="email" name="email" autocomplete="username" required/></label>
        <label class="field"><span>Password</span><input type="password" name="password" autocomplete="current-password" required/></label>
        <button class="btn btn--pop" type="submit" style="width:100%">Sign in</button>
      </form>
    </div>
  </div></div>`;
  return page("Dustonic Admin — Sign in", body);
}

function statusPill(status) {
  return html`<span class="pill ${status}">${status}</span>`;
}

function tierPill(tier) {
  return tier ? html`<span class="pill ${tier}">${tier}</span>` : "";
}

function requestRow(r) {
  const decided = r.status !== "pending";
  const tierSelect = html`<select name="tier">
      <option value="pro">Pro</option>
      <option value="free">Free</option>
    </select>`;
  const actions = decided
    ? html`<span class="muted">${r.tier ? raw(tierPill(r.tier)) : "—"} ${r.licenseKey ? raw(html`<span class="mono">${r.licenseKey}</span>`) : ""}</span>`
    : html`<div class="row-actions">
        <form class="inline" method="post" action="/admin/requests/${r.id}/approve">
          ${raw(tierSelect)}
          <button class="btn btn--pop" type="submit">Approve + email key</button>
        </form>
        <form class="inline" method="post" action="/admin/requests/${r.id}/reject">
          <button class="btn btn--bad" type="submit">Reject</button>
        </form>
      </div>`;
  return html`<tr>
    <td><b>${r.name || "—"}</b><br/><a href="mailto:${r.email}">${r.email}</a>${r.company ? raw(html`<br/><span class="muted">${r.company}</span>`) : ""}</td>
    <td>${r.plan || "—"}<br/><span class="msg">${r.message || ""}</span></td>
    <td>${raw(statusPill(r.status))}<br/><span class="muted" style="font-size:12px">${new Date(r.createdAt).toLocaleString()}</span></td>
    <td>${raw(actions)}</td>
  </tr>`;
}

function tierOptions(selected) {
  return ["free", "pro"].map(
    (t) =>
      html`<option value="${t}"${t === selected ? raw(" selected") : ""}>${t[0].toUpperCase() + t.slice(1)}</option>`,
  );
}

function sourceLabel(l) {
  if (l.source === "dodo")
    return html`<span class="pill" style="background:#e1f4ff;color:#0b6ca8;font-size:10px">dodo</span>`;
  if (l.source === "admin" || l.requestId)
    return html`<span class="pill" style="background:#f5f0ff;color:var(--pop);font-size:10px">admin</span>`;
  return html`<span class="pill" style="background:#eef0f4;color:#444;font-size:10px">manual</span>`;
}

function emailDeliveryLabel(l) {
  if (l.emailDelivered === true)
    return html`<span style="color:var(--ok);font-size:11px" title="Email delivered">&#x2709; sent</span>`;
  if (l.emailDelivered === false)
    return html`<span style="color:var(--bad);font-size:11px" title="Email failed">&#x2709; failed</span>`;
  return html`<span class="muted" style="font-size:11px">—</span>`;
}

function validityLabel(l) {
  if (!l.expiresAt) {
    // Dodo subscription without expiresAt (legacy): show "subscription" if it
    // has a subscriptionId, "lifetime" otherwise.
    if (l.source === "dodo" && l.dodo?.subscriptionId) {
      return html`<span class="muted" style="font-size:11px">subscription</span>`;
    }
    return html`<span class="muted" style="font-size:11px">lifetime</span>`;
  }
  const exp = new Date(l.expiresAt);
  const expired = exp <= new Date();
  if (expired)
    return html`<span style="color:var(--bad);font-size:11px" title="${exp.toLocaleDateString()}">expired</span>`;
  return html`<span style="font-size:11px" title="${exp.toLocaleDateString()}">${exp.toLocaleDateString()}</span>`;
}

function licenseRow(l, redemptions) {
  const key = encodeURIComponent(l.key);
  const changeTier =
    l.status === "active"
      ? html`<form class="inline" method="post" action="/admin/licenses/${key}/downgrade">
          <select name="tier">${raw(tierOptions(l.tier))}</select>
          <button class="btn" type="submit">Set tier</button>
        </form>`
      : "";
  const setValidity =
    l.status === "active"
      ? html`<form class="inline" method="post" action="/admin/licenses/${key}/validity">
          <select name="validityMonths" style="font-size:11px">
            <option value="">Lifetime</option>
            <option value="1">1 month</option>
            <option value="3">3 months</option>
            <option value="6">6 months</option>
            <option value="12">1 year</option>
            <option value="24">2 years</option>
          </select>
          <button class="btn" type="submit" style="font-size:11px">Set validity</button>
        </form>`
      : "";
  const revoke =
    l.status === "active"
      ? html`<form class="inline" method="post" action="/admin/licenses/${key}/revoke">
          <button class="btn btn--bad" type="submit">Revoke</button>
        </form>`
      : html`<span class="muted">revoked ${l.revokedAt ? new Date(l.revokedAt).toLocaleDateString() : ""}</span>`;
  const promoUsed = redemptions.find((r) => r.licenseKey === l.key);
  const downgradeInfo = l.downgradedAt
    ? html`<br/><span class="muted" style="font-size:11px">downgraded${l.downgradeReason === "validity_expired" ? " (expired)" : ""}</span>`
    : "";
  const lastActive = l.lastValidatedAt
    ? html`<span class="muted" style="font-size:11px" title="Last validated">${new Date(l.lastValidatedAt).toLocaleDateString()}</span>`
    : html`<span class="muted" style="font-size:11px">never</span>`;
  return html`<tr>
    <td class="mono" style="font-size:12px">${l.key}</td>
    <td>${raw(tierPill(l.tier))}${raw(downgradeInfo)}</td>
    <td><a href="mailto:${l.email}">${l.email}</a>${l.name ? raw(html`<br/><span class="muted" style="font-size:11px">${l.name}</span>`) : ""}</td>
    <td>${raw(sourceLabel(l))}</td>
    <td>${raw(statusPill(l.status))}</td>
    <td>${raw(emailDeliveryLabel(l))}</td>
    <td>${promoUsed ? raw(html`<span class="mono" style="font-size:11px;color:var(--pop)">${promoUsed.code}</span>`) : raw(html`<span class="muted" style="font-size:11px">—</span>`)}</td>
    <td>${raw(validityLabel(l))}</td>
    <td>${raw(lastActive)}</td>
    <td><span class="muted" style="font-size:12px">${new Date(l.createdAt).toLocaleDateString()}</span></td>
    <td><div class="row-actions">${raw(changeTier)}${raw(setValidity)}${raw(revoke)}</div></td>
  </tr>`;
}

function promoStatusPill(p) {
  if (p.status !== "active") return statusPill("revoked");
  if (p.expiresAt && Date.parse(p.expiresAt) <= Date.now()) {
    return html`<span class="pill revoked">expired</span>`;
  }
  return statusPill("active");
}

function promoRow(p, redemptionCount) {
  const code = encodeURIComponent(p.code);
  const scope =
    p.restrictedTiers && p.restrictedTiers.length
      ? p.restrictedTiers.join(", ")
      : "all paid";
  const expires = p.expiresAt
    ? new Date(p.expiresAt).toLocaleDateString()
    : "never";
  const usage = `${redemptionCount}${p.usageLimit != null ? ` / ${p.usageLimit}` : ""}`;
  const revoke =
    p.status === "active"
      ? html`<form class="inline" method="post" action="/admin/promos/${code}/revoke" onsubmit="return confirm('Revoke ${esc(p.code)}? It will stop working immediately.')">
          <button class="btn btn--bad" type="submit">Revoke</button>
        </form>`
      : html`<span class="muted">revoked</span>`;
  return html`<tr>
    <td class="mono"><b>${p.code}</b></td>
    <td>${String(p.percentOff)}%${p.subscriptionCycles ? raw(html`<br/><span class="muted" style="font-size:11px">${String(p.subscriptionCycles)} cycle${p.subscriptionCycles > 1 ? "s" : ""} only</span>`) : ""}</td>
    <td>${scope}</td>
    <td>${usage}</td>
    <td>${expires}</td>
    <td>${raw(promoStatusPill(p))}</td>
    <td>${raw(revoke)}</td>
  </tr>`;
}

function redemptionRow(r) {
  return html`<tr>
    <td class="mono">${r.code}</td>
    <td><a href="mailto:${r.email}">${r.email || "—"}</a></td>
    <td class="mono" style="font-size:12px">${r.licenseKey || "—"}</td>
    <td>${r.flagged ? raw(html`<span class="pill rejected">flagged</span><br/><span class="muted" style="font-size:11px">${r.flagReason || ""}</span>`) : raw(html`<span class="pill approved">ok</span>`)}</td>
    <td><span class="muted" style="font-size:12px">${new Date(r.redeemedAt).toLocaleString()}</span></td>
  </tr>`;
}

const PROMO_ERROR_TEXT = {
  invalid_code: "Code must be 3–40 chars: A–Z, 0–9, dash or underscore.",
  invalid_percent: "Percent off must be between 1 and 100.",
  code_exists: "A promo with that code already exists.",
  dodo_not_configured: "Dodo API key is not configured on the server.",
  dodo_create_failed: "Dodo rejected the discount. Check the code/params.",
};

export function renderDashboard({
  requests,
  licenses,
  promos = [],
  redemptions = [],
  promoApiReady = false,
  promoError = "",
}) {
  const pending = requests.filter((r) => r.status === "pending");
  const decided = requests.filter((r) => r.status !== "pending");

  const redemptionCount = (code) =>
    redemptions.filter((r) => r.code === code).length;
  const activePromos = promos.filter((p) => p.status === "active");
  const promoTable = promos.length
    ? html`<table><thead><tr><th>Code</th><th>Off</th><th>Plans</th><th>Used</th><th>Expires</th><th>Status</th><th></th></tr></thead>
        <tbody>${raw(promos.map((p) => promoRow(p, redemptionCount(p.code))))}</tbody></table>`
    : html`<div class="empty">No promo codes yet.</div>`;

  const flagged = redemptions.filter((r) => r.flagged);
  const redemptionTable = redemptions.length
    ? html`<table><thead><tr><th>Code</th><th>Account</th><th>License</th><th>Check</th><th>When</th></tr></thead>
        <tbody>${raw(redemptions.slice(-50).reverse().map(redemptionRow))}</tbody></table>`
    : html`<div class="empty">No promo redemptions yet.</div>`;

  const pendingTable = pending.length
    ? html`<table><thead><tr><th>Requester</th><th>Plan / message</th><th>Status</th><th>Action</th></tr></thead>
        <tbody>${raw(pending.map(requestRow))}</tbody></table>`
    : html`<div class="empty">No pending requests.</div>`;

  const decidedTable = decided.length
    ? html`<table><thead><tr><th>Requester</th><th>Plan / message</th><th>Status</th><th>Outcome</th></tr></thead>
        <tbody>${raw(decided.map(requestRow))}</tbody></table>`
    : html`<div class="empty">No decided requests yet.</div>`;

  const licenseTable = licenses.length
    ? html`<table><thead><tr><th>Key</th><th>Tier</th><th>Email</th><th>Source</th><th>Status</th><th>Email</th><th>Promo</th><th>Validity</th><th>Last&nbsp;active</th><th>Issued</th><th></th></tr></thead>
        <tbody>${raw(licenses.map((l) => licenseRow(l, redemptions)))}</tbody></table>`
    : html`<div class="empty">No licenses issued yet.</div>`;

  const body = html`<div class="wrap">
    <header class="bar">
      <div class="brand">Dustonic <small>Admin</small></div>
      <form method="post" action="/admin/logout"><button class="btn btn--ghost" type="submit">Sign out</button></form>
    </header>

    <h1>Access requests</h1>
    <p class="muted">Approving emails a license key to the requester and unlocks their tier in the app.</p>

    <h2>Pending (${String(pending.length)})</h2>
    <div class="card">${raw(pendingTable)}</div>

    <h2>Issue a key manually</h2>
    <div class="card">
      <form class="row-actions" method="post" action="/admin/licenses/create" style="flex-wrap:wrap">
        <input type="email" name="email" placeholder="customer@email.com" required/>
        <input type="text" name="name" placeholder="Name (optional)"/>
        <select name="tier"><option value="pro">Pro</option><option value="free">Free</option></select>
        <select name="validityMonths" title="License validity (auto-downgrades to Free after)">
          <option value="">Lifetime</option>
          <option value="1">1 month</option>
          <option value="3">3 months</option>
          <option value="6">6 months</option>
          <option value="12">1 year</option>
          <option value="24">2 years</option>
        </select>
        <label class="muted" style="display:inline-flex;align-items:center;gap:6px;font-size:13px"><input type="checkbox" name="email_key" value="1" checked style="width:auto"/> email the key</label>
        <button class="btn btn--pop" type="submit">Generate key</button>
      </form>
    </div>

    <h2>Issued licenses (${String(licenses.length)})</h2>
    <p class="muted" style="margin-top:-4px">Revoke kills the key (refund/chargeback). "Set tier" downgrades to Free/Pro while keeping the key valid.</p>
    <form method="post" action="/admin/licenses/backfill-validity" style="margin-bottom:8px">
      <button class="btn" type="submit" title="Auto-detect billing period from Dodo product IDs and set correct expiresAt on subscription licenses currently showing lifetime">Backfill Dodo validity</button>
    </form>
    <div class="card">${raw(licenseTable)}</div>

    <h1 style="margin-top:36px">Promotions</h1>
    <p class="muted">Promo codes are created in Dodo (so the discount actually applies at checkout) and mirrored here. One promo per account, first-use only — enforced by the redemption ledger below.</p>

    ${promoError ? raw(html`<div class="err">${PROMO_ERROR_TEXT[promoError] || promoError}</div>`) : ""}
    ${promoApiReady ? "" : raw(html`<div class="note">Dodo API key isn't configured on the server, so new promo codes can't be created until it is set.</div>`)}

    <h2>Create a promo code</h2>
    <div class="card">
      <form class="row-actions" method="post" action="/admin/promos/create">
        <input type="text" name="code" placeholder="LAUNCH50" required style="text-transform:uppercase" pattern="[A-Za-z0-9_-]{3,40}"/>
        <input type="number" name="percent" placeholder="% off" min="1" max="100" step="1" required style="width:90px"/>
        <input type="text" name="name" placeholder="Label (optional)"/>
        <select name="usageLimit" title="Total redemptions allowed">
          <option value="">No usage cap</option>
          <option value="1">1 use total</option>
          <option value="50">50 uses</option>
          <option value="100">100 uses</option>
          <option value="500">500 uses</option>
          <option value="1000">1000 uses</option>
        </select>
        <select name="validityCycles" title="How many billing cycles the discount applies">
          <option value="1" selected>1 cycle (first only)</option>
          <option value="2">2 cycles</option>
          <option value="3">3 cycles</option>
          <option value="6">6 cycles</option>
          <option value="12">12 cycles</option>
          <option value="">All cycles (forever)</option>
        </select>
        <label class="muted" style="display:inline-flex;align-items:center;gap:6px;font-size:13px"><input type="checkbox" name="tiers" value="pro" style="width:auto"/> Pro only</label>
        <label class="muted" style="display:inline-flex;align-items:center;gap:6px;font-size:13px">expires <input type="date" name="expiresAt" style="width:auto"/></label>
        <button class="btn btn--pop" type="submit"${promoApiReady ? "" : raw(" disabled")}>Create promo</button>
      </form>
    </div>

    <h2>Active &amp; past promos (${String(activePromos.length)} active)</h2>
    <div class="card">${raw(promoTable)}</div>

    <h2>Redemptions${flagged.length ? raw(html` — <span class="pill rejected">${String(flagged.length)} flagged</span>`) : ""}</h2>
    <p class="muted" style="margin-top:-4px">A "flagged" redemption means the same account tried to use a second promo (stacking) — the discount still applied at Dodo, but it's surfaced here for review.</p>
    <div class="card">${raw(redemptionTable)}</div>

    <h2>Decided requests (${String(decided.length)})</h2>
    <div class="card">${raw(decidedTable)}</div>
  </div>`;
  return page("Dustonic Admin", body);
}

export { esc };
