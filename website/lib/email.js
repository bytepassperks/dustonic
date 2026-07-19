// Thin Mailgun wrapper shared by the contact form and license issuance.

const CONTACT_FROM =
  process.env.CONTACT_FROM || "Dustonic <noreply@dustonic.com>";
const MAILGUN_API_KEY = process.env.MAILGUN_API_KEY;
const MAILGUN_DOMAIN = process.env.MAILGUN_DOMAIN;
const MAILGUN_BASE_URL =
  process.env.MAILGUN_BASE_URL || "https://api.mailgun.net";

export function isMailConfigured() {
  return Boolean(MAILGUN_API_KEY && MAILGUN_DOMAIN);
}

export async function sendMail({ to, subject, text, replyTo, from }) {
  if (!isMailConfigured()) {
    throw new Error("Mailgun is not configured");
  }
  const body = new URLSearchParams();
  body.set("from", from || CONTACT_FROM);
  body.set("to", to);
  body.set("subject", subject);
  body.set("text", text);
  if (replyTo) body.set("h:Reply-To", replyTo);

  const auth = Buffer.from(`api:${MAILGUN_API_KEY}`).toString("base64");
  const res = await fetch(`${MAILGUN_BASE_URL}/v3/${MAILGUN_DOMAIN}/messages`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${auth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(`Mailgun responded ${res.status}: ${detail}`);
  }
}
