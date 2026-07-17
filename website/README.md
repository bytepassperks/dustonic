# Dustonic — Website

The marketing site for [dustonic.com](https://dustonic.com). Hand-built,
no front-end framework: static HTML/CSS/JS served by a tiny Express server that
also handles the contact form.

## Run locally

```bash
cd website
npm install
cp .env.example .env   # optional; fill in Mailgun later
npm start              # http://localhost:3000
```

## Contact form and license portal

`POST /api/contact` validates the submission, persists it to
`data/contact-submissions.jsonl`, and — once Mailgun is configured — emails it to
`CONTACT_TO`.

| Env var | Purpose |
| --- | --- |
| `CONTACT_TO` | Inbox that receives inquiries |
| `CONTACT_FROM` | From header (verified Mailgun sender) |
| `MAILGUN_API_KEY` | Mailgun private API key |
| `MAILGUN_DOMAIN` | Verified Mailgun sending domain |
| `MAILGUN_BASE_URL` | `https://api.mailgun.net` (US) or `https://api.eu.mailgun.net` (EU) |

Until `MAILGUN_API_KEY` + `MAILGUN_DOMAIN` are set, submissions are still captured
to disk and the API responds `{ ok: true, delivered: false }` — nothing is dropped.

## Deploy to Render

Create a **Web Service** from this repo with:

- **Root Directory**: `website`
- **Build Command**: `npm install`
- **Start Command**: `npm start`
- **Environment**: add the variables above.

Render injects `PORT` automatically; the server reads it.

## Dodo Payments

The webhook and checkout integration remain inert until configured:

- `DODO_WEBHOOK_SECRET`
- `DODO_PAYMENTS_API_KEY`
- `DODO_PRO_PRODUCT_IDS`
- `DODO_CHECKOUT_PRO_MONTHLY`
- `DODO_CHECKOUT_PRO_ANNUAL`
- `DODO_DEFAULT_TIER`

`POST /api/license/validate` returns the Free/Pro entitlement contract used by
the Dustonic desktop app. The admin portal is available at `/admin`; configure
`ADMIN_EMAIL`, `ADMIN_PASSWORD_HASH`, and `SESSION_SECRET` before using it.
