/**
 * Notification dispatcher.
 *
 * Pilot behaviour:
 *   - Submission confirmation: always send, on receipt of a new application.
 *   - Status change: per the user's instruction, send on EVERY status change.
 *     (The pilot brief proposed throttling to "significant" transitions only
 *     and capping at one email per applicant per 24 hours; that filter is
 *     intentionally not in place yet so we can see every transition land.)
 *
 * Email transport:
 *   - Always written to disk in MAIL_OUT_DIR (one folder per send) — this is
 *     the audit trail and stays in place even when a real provider is wired
 *     up. Open body.html in a browser to preview.
 *   - If RESEND_API_KEY is set, the email is ALSO sent via Resend's HTTP API.
 *     If unset (local dev or pre-domain-verification), the disk write is the
 *     only delivery channel.
 *
 * Content rules:
 *   - The email is a NUDGE, not a payload. No PII beyond the applicant's first
 *     name. The body always points back to the tracker for the actual detail.
 *   - One link per email — the tracker deeplink for that application.
 */

const fs = require('fs');
const path = require('path');
const { pool } = require('./db');

const MAIL_DIR = process.env.MAIL_OUT_DIR || path.join(__dirname, 'mail-out');
let MAIL_DIR_WRITABLE = false;
try {
  if (!fs.existsSync(MAIL_DIR)) fs.mkdirSync(MAIL_DIR, { recursive: true });
  MAIL_DIR_WRITABLE = true;
} catch (_) {
  // Vercel / read-only filesystem — skip disk writes, rely on Resend for delivery.
}

const TRACKER_BASE = process.env.TRACKER_BASE_URL || 'http://localhost:3030';
const OFFICER_BASE = process.env.OFFICER_BASE_URL || TRACKER_BASE;
const RESEND_API_KEY = process.env.RESEND_API_KEY;
// Resend's "onboarding@resend.dev" works without domain verification — useful
// for first-deploy. Replace with no-reply@<verified-domain> once DNS is set.
const FROM_EMAIL = process.env.FROM_EMAIL || 'GovBB Tracker <onboarding@resend.dev>';

/* =========================================================
   Templates
   ========================================================= */

const STATUS_LABEL = {
  received: 'Received',
  under_review: 'Under review',
  action_needed: 'Action needed',
  approved: 'Approved',
  rejected: 'Not approved',
  completed: 'Completed'
};

function firstName(fullName) {
  return (fullName || '').trim().split(/\s+/)[0] || 'there';
}

function trackerUrl(code) {
  return `${TRACKER_BASE}/track/${encodeURIComponent(code)}`;
}

/** Confirmation email when an application is first submitted. */
function buildSubmissionEmail(app) {
  const name = firstName(app.applicant_name);
  const subject = `Application received — ${app.code}`;
  const text = [
    `Hi ${name},`,
    ``,
    `We've received your application for ${app.programme_name}.`,
    ``,
    `Your reference code is: ${app.code}`,
    ``,
    `Use this link to see the status of your application at any time:`,
    `${trackerUrl(app.code)}`,
    ``,
    `What happens next:`,
    `An officer will review your application within ${app.default_sla_days || 14} working days. We'll email you when the status changes.`,
    ``,
    `If you didn't submit this application, contact ${app.contact_email || 'mysce@barbados.gov.bb'}.`,
    ``,
    `— Ministry of Youth, Sport and Community Engagement`
  ].join('\n');

  const html = baseTemplate({
    headline: 'Application received',
    body: `
      <p>Hi ${name},</p>
      <p>We've received your application for <strong>${app.programme_name}</strong>.</p>
      <p>Your reference code is:</p>
      <p style="font-family:'JetBrains Mono', Menlo, Consolas, monospace; font-size:20px; font-weight:700; background:#fff9e9; border:2px solid #ffc726; padding:14px 18px; border-radius:6px; display:inline-block; letter-spacing:1px;">${app.code}</p>
      <p>Use this link to see the status of your application at any time:</p>
      <p><a class="cta" href="${trackerUrl(app.code)}">Track your application</a></p>
      <p><strong>What happens next</strong><br>
      An officer will review your application within ${app.default_sla_days || 14} working days. We'll email you when the status changes.</p>
      <p style="color:#595959; font-size:14px;">If you didn't submit this application, contact <a href="mailto:${app.contact_email || 'mysce@barbados.gov.bb'}">${app.contact_email || 'mysce@barbados.gov.bb'}</a>.</p>
    `
  });

  return { subject, text, html };
}

/** Email when an officer changes status. Short by design. */
function buildStatusChangeEmail(app, event) {
  const name = firstName(app.applicant_name);
  const label = STATUS_LABEL[event.status] || event.status;
  const subject = `Update on your ${app.programme_name} application — ${app.code}`;
  const lead = {
    received: `We've logged your application.`,
    under_review: `An officer is now reviewing your application.`,
    action_needed: `We need something from you to keep your application moving.`,
    approved: `We've approved your application.`,
    rejected: `We weren't able to approve this application.`,
    completed: `Your application is complete.`
  }[event.status] || `Your application has been updated.`;

  const text = [
    `Hi ${name},`,
    ``,
    `Your ${app.programme_name} application (${app.code}) is now: ${label}.`,
    ``,
    lead,
    ``,
    `See the full detail and what to do next on the tracker:`,
    `${trackerUrl(app.code)}`,
    ``,
    `— Ministry of Youth, Sport and Community Engagement`
  ].join('\n');

  const html = baseTemplate({
    headline: `Status: ${label}`,
    body: `
      <p>Hi ${name},</p>
      <p>Your <strong>${app.programme_name}</strong> application (<span style="font-family:'JetBrains Mono', Menlo, Consolas, monospace;">${app.code}</span>) is now:</p>
      <p><span style="display:inline-block; background:#e5e9f2; color:#00267f; font-weight:700; padding:6px 14px; border-radius:999px;">${label}</span></p>
      <p>${lead}</p>
      <p><a class="cta" href="${trackerUrl(app.code)}">See the detail and what to do next</a></p>
    `
  });

  return { subject, text, html };
}

/** Shared HTML wrapper — alpha.gov.bb-flavoured email chrome. */
function baseTemplate({ headline, body }) {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>${escapeHtml(headline)}</title>
<style>
  body { font-family: -apple-system, system-ui, "Segoe UI", Roboto, sans-serif; background:#f4f4f4; margin:0; padding:24px; color:#000; }
  .wrap { max-width: 600px; margin: 0 auto; background:#fff; border:1px solid #e0e4e9; }
  .bar { background:#00267f; color:#fff; padding:10px 24px; font-size:13px; }
  .header { background:#ffc726; padding:18px 24px; font-weight:800; font-size:20px; letter-spacing:-0.01em; }
  .alpha { background:#e5e9f2; padding:10px 24px; font-size:13px; }
  .body { padding:24px; line-height:1.55; font-size:16px; }
  .body h1 { font-size:24px; margin:0 0 16px; }
  .body p { margin:0 0 14px; }
  .cta { display:inline-block; background:#00654a; color:#fff !important; text-decoration:none; padding:10px 18px; font-weight:700; border-radius:4px; }
  .footer { background:#00267f; color:#fff; padding:18px 24px; font-size:13px; line-height:1.5; }
  .footer a { color:#fff; }
</style>
</head>
<body>
  <div class="wrap">
    <div class="bar">Official email from the Government of Barbados</div>
    <div class="header">GovBB</div>
    <div class="alpha">This service is in <strong>Alpha</strong>. Your feedback helps us improve.</div>
    <div class="body">
      <h1>${escapeHtml(headline)}</h1>
      ${body}
    </div>
    <div class="footer">
      Ministry of Youth, Sport and Community Engagement<br>
      Bay Street, Bridgetown, BB11000, Barbados<br>
      You're getting this email because you applied to one of our programmes.
    </div>
  </div>
</body></html>`;
}

function escapeHtml(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

/* =========================================================
   Send
   ========================================================= */

function safeFilename(s) {
  return s.replace(/[^a-zA-Z0-9_-]+/g, '_').slice(0, 80);
}

/** Send via Resend's HTTP API. Returns the message id, or null on error. */
async function sendViaResend({ to, subject, text, html }) {
  if (!RESEND_API_KEY) return null;
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ from: FROM_EMAIL, to: [to], subject, html, text })
    });
    if (!res.ok) {
      const err = await res.text().catch(() => '');
      console.error(`[mail] Resend ${res.status}:`, err.slice(0, 300));
      return null;
    }
    const data = await res.json();
    return data && data.id ? data.id : null;
  } catch (e) {
    console.error('[mail] Resend network error:', e.message);
    return null;
  }
}

function writeEmailToDisk({ to, subject, text, html, application_id, kind }) {
  if (!MAIL_DIR_WRITABLE) return null;
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const slug = safeFilename(`${stamp}_${kind}_${to}_${subject}`);
  const dir = path.join(MAIL_DIR, slug);
  fs.mkdirSync(dir, { recursive: true });

  const meta = `From: GovBB Tracker <no-reply@alpha.gov.bb>
To: ${to}
Subject: ${subject}
Date: ${new Date().toUTCString()}
Application: ${application_id}
Kind: ${kind}
`;

  fs.writeFileSync(path.join(dir, 'meta.txt'), meta);
  fs.writeFileSync(path.join(dir, 'body.txt'), text);
  fs.writeFileSync(path.join(dir, 'body.html'), html);

  return path.relative(__dirname, dir);
}

async function sendSubmissionEmail(app) {
  const { subject, text, html } = buildSubmissionEmail(app);
  const bodyPath = writeEmailToDisk({
    to: app.applicant_email,
    subject, text, html,
    application_id: app.id,
    kind: 'submission'
  });
  const messageId = await sendViaResend({ to: app.applicant_email, subject, text, html });
  await pool.query(`
    INSERT INTO notifications (application_id, kind, channel, recipient, subject, body_path)
    VALUES ($1, 'submission', 'email', $2, $3, $4)
  `, [app.id, app.applicant_email, subject, bodyPath]);
  console.log(`[mail] submission → ${app.applicant_email} (${app.code})${messageId ? ' resend:' + messageId : ' [disk only]'}`);
}

async function sendStatusChangeEmail(app, event) {
  const { subject, text, html } = buildStatusChangeEmail(app, event);
  const bodyPath = writeEmailToDisk({
    to: app.applicant_email,
    subject, text, html,
    application_id: app.id,
    kind: 'status_change'
  });
  const messageId = await sendViaResend({ to: app.applicant_email, subject, text, html });
  await pool.query(`
    INSERT INTO notifications (application_id, kind, channel, recipient, subject, body_path)
    VALUES ($1, 'status_change', 'email', $2, $3, $4)
  `, [app.id, app.applicant_email, subject, bodyPath]);
  console.log(`[mail] status_change → ${app.applicant_email} (${app.code} → ${event.status})${messageId ? ' resend:' + messageId : ' [disk only]'}`);
}

/* =========================================================
   Diagnostics — used by the /healthz/email endpoint
   ========================================================= */

/** Static config snapshot. No secrets leaked; the key's presence is reported
 *  but the key itself is never returned. */
function emailConfig() {
  let mailOutCount = 0;
  if (MAIL_DIR_WRITABLE) {
    try { mailOutCount = fs.readdirSync(MAIL_DIR).length; } catch (_) {}
  }

  return {
    resend_api_key_set: Boolean(RESEND_API_KEY),
    from_email: FROM_EMAIL,
    tracker_base_url: TRACKER_BASE,
    mail_out_dir: MAIL_DIR,
    mail_out_writable: MAIL_DIR_WRITABLE,
    mail_out_folders: mailOutCount
  };
}

/** Send a real test email through Resend (and write to disk like normal).
 *  Returns { ok, message_id, disk_path, error }. Used by an officer-only
 *  diagnostic endpoint. */
async function sendTestEmail({ to, sentByOfficer }) {
  if (!to || typeof to !== 'string' || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(to)) {
    return { ok: false, error: 'A valid `to` address is required.' };
  }
  const subject = `GovBB Tracker — email test`;
  const text = [
    `Hi,`,
    ``,
    `This is a test email from the GovBB Application Tracker, sent at ${new Date().toUTCString()}.`,
    ``,
    `If you're reading this in an inbox, end-to-end delivery via Resend is working.`,
    ``,
    `Triggered by: ${sentByOfficer || 'an officer'}`,
    `Tracker base URL: ${TRACKER_BASE}`,
    ``,
    `— GovBB Tracker`
  ].join('\n');

  const html = baseTemplate({
    headline: 'Email test',
    body: `
      <p>This is a test email from the <strong>GovBB Application Tracker</strong>.</p>
      <p>If you're reading this in an inbox, end-to-end delivery via Resend is working.</p>
      <p style="color:#595959; font-size:14px;">
        Sent at: ${new Date().toUTCString()}<br>
        Triggered by: ${escapeHtml(sentByOfficer || 'an officer')}<br>
        Tracker base URL: <a href="${TRACKER_BASE}">${escapeHtml(TRACKER_BASE)}</a>
      </p>
    `
  });

  const diskPath = writeEmailToDisk({
    to, subject, text, html,
    application_id: null,
    kind: 'test'
  });

  if (!RESEND_API_KEY) {
    return {
      ok: true,
      message_id: null,
      disk_path: diskPath,
      delivered_via: 'disk-only',
      note: 'RESEND_API_KEY not set — email written to disk only, no real send attempted.'
    };
  }

  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ from: FROM_EMAIL, to: [to], subject, html, text })
    });
    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      return {
        ok: false,
        message_id: null,
        disk_path: diskPath,
        delivered_via: 'disk-only',
        error: `Resend ${res.status}: ${errText.slice(0, 500)}`
      };
    }
    const data = await res.json();
    return {
      ok: true,
      message_id: data && data.id ? data.id : null,
      disk_path: diskPath,
      delivered_via: 'resend'
    };
  } catch (e) {
    return {
      ok: false,
      message_id: null,
      disk_path: diskPath,
      delivered_via: 'disk-only',
      error: `Network error: ${e.message}`
    };
  }
}

/* =========================================================
   Officer password setup / reset email
   ========================================================= */

/**
 * Send a "set your password" link to an officer. Used in two flows:
 *   - new officer creation (purpose='set_initial', subject "Welcome…")
 *   - admin-triggered password reset (purpose='reset', subject "Reset your password")
 *
 * The link expires after PASSWORD_TOKEN_TTL_HOURS (default 24).
 */
async function sendPasswordSetupEmail({ officer, plaintextToken, ttlHours, isInitial }) {
  const link = `${OFFICER_BASE}/set-password/${encodeURIComponent(plaintextToken)}`;
  const subject = isInitial
    ? `Set up your GovBB Tracker account`
    : `Reset your GovBB Tracker password`;
  const lead = isInitial
    ? `An admin has created an account for you on the GovBB Application Tracker. Set a password to sign in.`
    : `You can set a new password using the link below.`;

  const text = [
    `Hi ${firstName(officer.name)},`,
    ``,
    lead,
    ``,
    `Set your password: ${link}`,
    ``,
    `This link is valid for ${ttlHours || 24} hours and can only be used once.`,
    ``,
    `If you didn't expect this email, you can ignore it.`,
    ``,
    `— GovBB Tracker`
  ].join('\n');

  const html = baseTemplate({
    headline: isInitial ? 'Set up your account' : 'Reset your password',
    body: `
      <p>Hi ${firstName(officer.name)},</p>
      <p>${lead}</p>
      <p><a class="cta" href="${link}">Set your password</a></p>
      <p style="color:#595959; font-size:13.5px;">
        This link is valid for ${ttlHours || 24} hours and can only be used once.<br>
        If you didn't expect this email, you can ignore it.
      </p>
      <p style="color:#999; font-size:12px;">If the button doesn't work, copy and paste this URL into your browser:<br>${link}</p>
    `
  });

  const bodyPath = writeEmailToDisk({
    to: officer.email,
    subject, text, html,
    application_id: null,
    kind: isInitial ? 'password_setup' : 'password_reset'
  });
  const messageId = await sendViaResend({ to: officer.email, subject, text, html });
  console.log(`[mail] ${isInitial ? 'password_setup' : 'password_reset'} → ${officer.email}${messageId ? ' resend:' + messageId : ' [disk only]'}`);
  return { ok: true, message_id: messageId, disk_path: bodyPath, delivered_via: messageId ? 'resend' : 'disk-only' };
}

module.exports = {
  sendSubmissionEmail,
  sendStatusChangeEmail,
  sendPasswordSetupEmail,
  emailConfig,
  sendTestEmail,
  MAIL_DIR
};
