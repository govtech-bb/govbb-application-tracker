/**
 * GovBB Application Tracker — pilot server.
 *
 * Routes:
 *   GET  /                          citizen tracker landing
 *   GET  /track/:code               citizen tracker detail (deeplinkable)
 *   GET  /chat                      citizen tracker, full chat
 *   GET  /confirmation/:code        confirmation page after submitting a form
 *   GET  /submit-test               demo: pretend to submit a form
 *   GET  /officer/login             officer sign-in page
 *   GET  /officer                   officer console (auth required)
 *
 *   POST /api/officer/login         sign in
 *   POST /api/officer/logout        sign out
 *   GET  /api/me                    current officer or 401
 *
 *   GET  /api/programmes            list of programmes (for the test form)
 *   GET  /api/sample-codes          list of seeded codes (for the demo)
 *
 *   POST /api/webhooks/form-submitted   form intake (called by alpha.gov.bb forms)
 *   GET  /api/applications/:code        public lookup by reference code
 *
 *   Officer routes (require sign-in; non-admin officers only see programmes
 *   they're assigned to via officer_programmes):
 *     GET    /api/officer/applications
 *     GET    /api/officer/applications/:id
 *     PATCH  /api/officer/applications/:id
 *     POST   /api/officer/applications/:id/assign-me
 *
 *   Admin routes (require is_admin):
 *     GET    /api/admin/officers              list officers
 *     POST   /api/admin/officers              create officer
 *     PATCH  /api/admin/officers/:id          update officer
 *     POST   /api/admin/officers/:id/password reset password
 *     GET    /api/admin/officers/:id/programmes  list assignments
 *     PUT    /api/admin/officers/:id/programmes  set assignments (whole-set)
 *
 *     GET    /api/admin/programmes            list programmes (full detail)
 *     POST   /api/admin/programmes            create programme
 *     PATCH  /api/admin/programmes/:id        update programme (incl. accepting toggle)
 *
 *     GET    /api/admin/dashboard             metrics
 *     GET    /api/admin/audit-log             paginated audit log
 */

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');

const {
  db,
  insertStatusEvent,
  getApplicationByCode,
  getApplicationById,
  listApplicationsForOfficer,
  listProgrammesForOfficer,
  officerCanAccessApplication
} = require('./db');
const { generateUniqueCode } = require('./codes');
const { authenticateOfficer, requireOfficer, requireAdmin } = require('./auth');
const { requireApiKey } = require('./apikey');
const {
  sendSubmissionEmail,
  sendStatusChangeEmail,
  sendPasswordSetupEmail,
  emailConfig,
  sendTestEmail
} = require('./notifications');
const { logAction, requestMeta, listAuditLog } = require('./auditLog');
const {
  issueToken,
  findValidToken,
  consumeTokenAndSetPassword,
  validatePassword,
  hashPassword,
  RULES: PASSWORD_RULES,
  TOKEN_TTL_HOURS
} = require('./passwords');

const app = express();
const PORT = process.env.PORT || 3030;
const IS_PROD = process.env.NODE_ENV === 'production';

// Render terminates HTTPS at its edge and forwards via HTTP. Without this,
// Express won't honour X-Forwarded-Proto / X-Forwarded-For, so secure cookies
// and IP detection would break.
app.set('trust proxy', 1);

// Fail fast in production if the session secret hasn't been set. In dev a
// hard-coded fallback is fine; in production it would let attackers forge
// session cookies.
if (IS_PROD && !process.env.SESSION_SECRET) {
  console.error('FATAL: SESSION_SECRET must be set in production.');
  process.exit(1);
}

app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-only-pilot-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PROD,                 // HTTPS-only in production
    maxAge: 1000 * 60 * 60 * 8
  }
}));

// Lightweight health check for Render's load balancer.
app.get('/healthz', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// Email config check — public, no secrets exposed.
app.get('/healthz/email', (req, res) => {
  const cfg = emailConfig();
  res.json({
    ok: cfg.resend_api_key_set && cfg.mail_out_writable,
    config: cfg,
    instructions: cfg.resend_api_key_set
      ? 'Looks configured. POST /api/officer/test-email with {"to":"you@example.com"} to send a real test (officer auth required).'
      : 'RESEND_API_KEY is not set — emails will land on disk only. Set it in Render env vars to enable real send.'
  });
});

// Officer-only: send a real test email.
app.post('/api/officer/test-email', requireOfficer, async (req, res) => {
  const { to } = req.body || {};
  const targetEmail = (to || '').trim() || req.session.officer.email || null;
  const result = await sendTestEmail({
    to: targetEmail,
    sentByOfficer: req.session.officer.username
  });
  logAction({
    actor: req.session.officer,
    action: 'test_email.send',
    target_kind: 'session',
    metadata: requestMeta(req, { to: targetEmail, ok: result.ok, delivered_via: result.delivered_via })
  });
  res.status(result.ok ? 200 : 502).json(result);
});

/* =========================================================
   Static + page routes
   ========================================================= */

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/track', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/track/:code', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/chat', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/confirmation/:code', (req, res) => res.sendFile(path.join(__dirname, 'confirmation.html')));
app.get('/submit-test', (req, res) => res.sendFile(path.join(__dirname, 'submit-test.html')));
app.get('/officer/login', (req, res) => res.sendFile(path.join(__dirname, 'officer-login.html')));
app.get('/officer', requireOfficer, (req, res) => res.sendFile(path.join(__dirname, 'officer.html')));
app.get('/set-password/:token', (req, res) => res.sendFile(path.join(__dirname, 'set-password.html')));

/* =========================================================
   Password setup / reset (public — token-protected)
   ========================================================= */

// Public read of the complexity rules so the live-hint UI can match the server.
app.get('/api/password-rules', (req, res) => {
  res.json({ rules: PASSWORD_RULES, ttl_hours: TOKEN_TTL_HOURS });
});

// Validate a token and return the officer's name+email so the page can greet
// them. Doesn't expose anything an attacker with the token couldn't already
// guess from the email they received.
app.get('/api/password-token/:token', (req, res) => {
  const t = findValidToken(req.params.token);
  if (!t || t.error) return res.status(400).json({ error: errorMessage(t && t.error), code: (t && t.error) || 'unknown' });
  res.json({
    valid: true,
    purpose: t.purpose,
    officer: { name: t.officer.name, email: t.officer.email },
    expires_at: t.expires_at
  });
});

// Set a new password using a valid token.
app.post('/api/set-password', (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'token and password required' });

  const t = findValidToken(token);
  if (!t || t.error) {
    logAction({ action: 'password.set_fail', metadata: requestMeta(req, { reason: t && t.error || 'unknown' }) });
    return res.status(400).json({ error: errorMessage(t && t.error), code: (t && t.error) || 'unknown' });
  }

  const v = validatePassword(password, { email: t.officer.email });
  if (!v.ok) return res.status(400).json({ error: v.errors[0], errors: v.errors });

  consumeTokenAndSetPassword(t.id, t.officer_id, hashPassword(password));
  logAction({
    action: 'password.set_success',
    target_kind: 'officer', target_id: t.officer_id,
    metadata: requestMeta(req, { purpose: t.purpose, officer_email: t.officer.email })
  });
  res.json({ ok: true, redirect_to: '/officer/login' });
});

function errorMessage(code) {
  switch (code) {
    case 'unknown':  return 'This link is not valid. It may have been mistyped.';
    case 'used':     return 'This link has already been used. If you need to set a new password, ask an admin to send another link.';
    case 'expired':  return 'This link has expired. Ask an admin to send a fresh one.';
    case 'inactive_officer': return 'This account has been deactivated.';
    default:         return 'This link is not valid.';
  }
}

/* =========================================================
   Auth API
   ========================================================= */

app.post('/api/officer/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const officer = authenticateOfficer(username, password);
  if (officer && officer._inactive) {
    logAction({ action: 'login.fail', metadata: requestMeta(req, { username, reason: 'inactive' }) });
    return res.status(403).json({ error: 'This account has been deactivated. Contact your admin.' });
  }
  if (!officer) {
    logAction({ action: 'login.fail', metadata: requestMeta(req, { username, reason: 'bad_credentials' }) });
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  req.session.officer = officer;
  logAction({
    actor: officer,
    action: 'login.success',
    target_kind: 'officer',
    target_id: officer.id,
    metadata: requestMeta(req)
  });
  res.json({ officer });
});

app.post('/api/officer/logout', (req, res) => {
  const actor = req.session.officer;
  if (actor) {
    logAction({
      actor,
      action: 'logout',
      target_kind: 'officer',
      target_id: actor.id,
      metadata: requestMeta(req)
    });
  }
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  if (!req.session.officer) return res.status(401).json({ error: 'Not authenticated' });
  res.json({ officer: req.session.officer });
});

/* =========================================================
   Public API
   ========================================================= */

app.get('/api/programmes', (req, res) => {
  // Public list — only programmes that are currently accepting are exposed.
  const rows = db.prepare(`
    SELECT code, name, ministry, default_sla_days, contact_email, contact_phone,
           accepting_applications
    FROM programmes
    WHERE accepting_applications = 1
    ORDER BY name
  `).all();
  res.json({ programmes: rows });
});

app.get('/api/sample-codes', (req, res) => {
  const rows = db.prepare(`
    SELECT a.code, p.name AS programme_name, ap.name AS applicant_name, a.current_status
    FROM applications a
    JOIN programmes p ON p.id = a.programme_id
    JOIN applicants ap ON ap.id = a.applicant_id
    ORDER BY a.created_at DESC
    LIMIT 12
  `).all();
  res.json({ codes: rows });
});

app.get('/api/applications/:code', (req, res) => {
  const app = getApplicationByCode(req.params.code.toUpperCase().trim());
  if (!app) return res.status(404).json({ error: 'Application not found' });
  res.json({
    application: {
      code: app.code,
      programme_code: app.programme_code,
      programme_name: app.programme_name,
      ministry: app.ministry,
      contact_email: app.contact_email,
      contact_phone: app.contact_phone,
      default_sla_days: app.default_sla_days,
      applicant_name: app.applicant_name,
      submitted_at: app.created_at,
      current_status: app.current_status,
      current_status_at: app.current_status_at,
      assigned_officer_name: app.assigned_officer_name,
      // Citizen timeline only includes events that have something to say to
      // the citizen. Internal-only rows (e.g. "Assign to me" — which writes a
      // status_event with the current status and no citizen_message so the
      // officer audit trail captures who picked up the case) are excluded.
      // Without this filter, those rows render on the public tracker as
      // "Not approved" or "Under review" with no body — confusing and
      // sometimes alarming.
      timeline: app.timeline
        .filter(t => t.citizen_message && t.citizen_message.trim())
        .map(t => ({
          status: t.status,
          message: t.citizen_message,
          at: t.created_at
        }))
    }
  });
});

/* =========================================================
   Form intake webhook — secured with API key.
   ========================================================= */

const CODE_PATTERN = /^[A-Z][A-Z0-9_-]*-\d{4}-[A-Z0-9]{6,16}$/;

app.post('/api/webhooks/form-submitted', requireApiKey, (req, res) => {
  const { code, programme_code, applicant, form_data, submitted_at } = req.body || {};

  if (typeof code !== 'string' || !CODE_PATTERN.test(code)) {
    return res.status(400).json({ error: 'code required, format: PROGRAMME-YEAR-XXXXXXX (uppercase letters/digits, 6–16 char suffix).' });
  }
  if (!programme_code) return res.status(400).json({ error: 'programme_code required' });
  if (!applicant || !applicant.name || !applicant.email) {
    return res.status(400).json({ error: 'applicant.name and applicant.email required' });
  }
  if (form_data !== undefined && (form_data === null || typeof form_data !== 'object' || Array.isArray(form_data))) {
    return res.status(400).json({ error: 'form_data must be a JSON object if present' });
  }

  const programme = db.prepare('SELECT * FROM programmes WHERE code = ?').get(programme_code);
  if (!programme) return res.status(404).json({ error: `Unknown programme: ${programme_code}` });

  // Idempotency: if this code already exists, return the existing record.
  const existing = db.prepare(`
    SELECT a.id, a.code, a.programme_id, ap.email AS applicant_email
    FROM applications a JOIN applicants ap ON ap.id = a.applicant_id
    WHERE a.code = ?
  `).get(code);
  if (existing) {
    if (existing.programme_id !== programme.id || existing.applicant_email !== applicant.email) {
      return res.status(409).json({
        error: `Code ${code} is already in use for a different submission.`,
        existing_application_id: existing.id
      });
    }
    return res.status(200).json({
      code: existing.code,
      idempotent: true,
      tracker_url: `/track/${encodeURIComponent(existing.code)}`,
      confirmation_url: `/confirmation/${encodeURIComponent(existing.code)}`
    });
  }

  const submittedSql = submitted_at && /^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?(\.\d+)?(Z)?$/.test(submitted_at)
    ? submitted_at.replace('T', ' ').replace('Z', '').split('.')[0]
    : null;

  // If the programme is closed, accept the submission anyway but flag it so
  // officers can see "this came in after the cut-off" at a glance.
  const flaggedAfterClose = programme.accepting_applications ? 0 : 1;

  const applicantId = db.prepare(`
    INSERT INTO applicants (name, email, phone) VALUES (?, ?, ?)
  `).run(applicant.name, applicant.email, applicant.phone || null).lastInsertRowid;

  const result = submittedSql
    ? db.prepare(`
        INSERT INTO applications (code, programme_id, applicant_id, current_status, current_status_at, form_data, flagged_after_close, created_at)
        VALUES (?, ?, ?, 'received', ?, ?, ?, ?)
      `).run(code, programme.id, applicantId, submittedSql, JSON.stringify(form_data || {}), flaggedAfterClose, submittedSql)
    : db.prepare(`
        INSERT INTO applications (code, programme_id, applicant_id, current_status, current_status_at, form_data, flagged_after_close)
        VALUES (?, ?, ?, 'received', datetime('now'), ?, ?)
      `).run(code, programme.id, applicantId, JSON.stringify(form_data || {}), flaggedAfterClose);

  const applicationId = result.lastInsertRowid;

  insertStatusEvent({
    application_id: applicationId,
    status: 'received',
    citizen_message: 'Application received and acknowledged.',
    internal_note: flaggedAfterClose
      ? `Pushed via API by client #${req.apiClient.id} (${req.apiClient.name}). Flagged: programme is not accepting applications.`
      : `Pushed via API by client #${req.apiClient.id} (${req.apiClient.name}).`,
    by_officer_id: null
  });

  logAction({
    actor: null,
    action: 'application.intake',
    target_kind: 'application',
    target_id: applicationId,
    after: { code, programme_code, flagged_after_close: flaggedAfterClose },
    metadata: requestMeta(req, { api_client: req.apiClient.name, applicant_email: applicant.email })
  });

  const fullApp = getApplicationById(applicationId);
  sendSubmissionEmail(fullApp).catch(e => console.error('Submission email failed:', e));

  res.status(201).json({
    code,
    flagged_after_close: Boolean(flaggedAfterClose),
    tracker_url: `/track/${encodeURIComponent(code)}`,
    confirmation_url: `/confirmation/${encodeURIComponent(code)}`
  });
});

/* =========================================================
   Officer API — caseload (filtered by programme assignments for non-admins)
   ========================================================= */

app.get('/api/officer/applications', requireOfficer, (req, res) => {
  const me = req.session.officer;
  res.json({ applications: listApplicationsForOfficer(me.id, me.is_admin) });
});

app.get('/api/officer/applications/:id', requireOfficer, (req, res) => {
  const me = req.session.officer;
  const id = parseInt(req.params.id, 10);
  if (!officerCanAccessApplication(me.id, me.is_admin, id)) {
    return res.status(403).json({ error: 'You do not have access to this application' });
  }
  const app = getApplicationById(id);
  if (!app) return res.status(404).json({ error: 'Not found' });
  res.json({ application: app });
});

app.patch('/api/officer/applications/:id', requireOfficer, (req, res) => {
  const me = req.session.officer;
  const id = parseInt(req.params.id, 10);
  if (!officerCanAccessApplication(me.id, me.is_admin, id)) {
    return res.status(403).json({ error: 'You do not have access to this application' });
  }
  const before = getApplicationById(id);
  if (!before) return res.status(404).json({ error: 'Not found' });

  const { status, citizen_message, internal_note } = req.body || {};
  if (!status) return res.status(400).json({ error: 'status required' });

  const allowed = JSON.parse(db.prepare('SELECT allowed_statuses FROM programmes WHERE id = ?').get(before.programme_id).allowed_statuses);
  if (!allowed.includes(status)) {
    return res.status(400).json({ error: `Status ${status} not allowed for this programme` });
  }

  const defaults = {
    received: 'Application received.',
    under_review: 'An officer is now reviewing your application.',
    action_needed: 'We need something from you. Please check your email.',
    approved: 'Decision: approved.',
    rejected: 'Decision: not approved.',
    completed: 'Your application is complete.'
  };
  const finalCitizenMessage = (citizen_message && citizen_message.trim()) || defaults[status] || 'Status updated.';

  insertStatusEvent({
    application_id: id,
    status,
    citizen_message: finalCitizenMessage,
    internal_note: (internal_note && internal_note.trim()) || null,
    by_officer_id: me.id
  });

  logAction({
    actor: me,
    action: 'application.status_change',
    target_kind: 'application',
    target_id: id,
    before: { status: before.current_status },
    after:  { status, citizen_message: finalCitizenMessage, internal_note: internal_note || null },
    metadata: requestMeta(req, { code: before.code })
  });

  const fullApp = getApplicationById(id);
  const lastEvent = fullApp.timeline[fullApp.timeline.length - 1];
  sendStatusChangeEmail(fullApp, lastEvent).catch(e => console.error('Status email failed:', e));

  res.json({ application: getApplicationById(id) });
});

app.post('/api/officer/applications/:id/assign-me', requireOfficer, (req, res) => {
  const me = req.session.officer;
  const id = parseInt(req.params.id, 10);
  if (!officerCanAccessApplication(me.id, me.is_admin, id)) {
    return res.status(403).json({ error: 'You do not have access to this application' });
  }
  const before = getApplicationById(id);
  if (!before) return res.status(404).json({ error: 'Not found' });

  db.prepare('UPDATE applications SET assigned_officer_id = ? WHERE id = ?')
    .run(me.id, id);

  insertStatusEvent({
    application_id: id,
    status: before.current_status,
    citizen_message: null,
    internal_note: `Assigned to ${me.name}.`,
    by_officer_id: me.id
  });

  logAction({
    actor: me,
    action: 'application.assign',
    target_kind: 'application',
    target_id: id,
    before: { assigned_officer_id: before.assigned_officer_id || null },
    after:  { assigned_officer_id: me.id },
    metadata: requestMeta(req, { code: before.code })
  });

  res.json({ application: getApplicationById(id) });
});

/* =========================================================
   Admin API — Officer management
   ========================================================= */

function getOfficerRow(id) {
  return db.prepare(`
    SELECT id, username, name, email, ministry, role, is_admin, is_active, created_at
    FROM officers
    WHERE id = ?
  `).get(id);
}

app.get('/api/admin/officers', requireOfficer, requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT id, username, name, email, ministry, role,
           is_admin, is_active, created_at,
           (SELECT COUNT(*) FROM officer_programmes op WHERE op.officer_id = officers.id) AS programme_count
    FROM officers
    ORDER BY name
  `).all();
  res.json({ officers: rows.map(o => ({ ...o, is_admin: Boolean(o.is_admin), is_active: Boolean(o.is_active) })) });
});

app.post('/api/admin/officers', requireOfficer, requireAdmin, async (req, res) => {
  const me = req.session.officer;
  const { name, email, ministry, role, is_admin } = req.body || {};

  if (!name || !email || !ministry || !role) {
    return res.status(400).json({ error: 'name, email, ministry and role required' });
  }
  const cleanEmail = String(email).trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(cleanEmail)) {
    return res.status(400).json({ error: 'email must be a valid address' });
  }
  // Email is the username — same uniqueness check.
  const exists = db.prepare('SELECT 1 FROM officers WHERE username = ? OR email = ?').get(cleanEmail, cleanEmail);
  if (exists) return res.status(409).json({ error: 'An officer with this email already exists' });

  // Officer is created with an unusable random password. The user sets a real
  // one via the email link. We mark them inactive until they do, so that
  // forgotten setup emails don't leave a half-onboarded account in limbo.
  const placeholderHash = hashPassword(crypto.randomBytes(24).toString('base64'));
  const result = db.prepare(`
    INSERT INTO officers (username, password_hash, name, email, ministry, role, is_admin, is_active)
    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
  `).run(cleanEmail, placeholderHash,
         name.trim(), cleanEmail, ministry.trim(), role.trim(),
         is_admin ? 1 : 0);
  const newId = result.lastInsertRowid;

  // Default: grant access to every programme. Admin can revoke later.
  const allProgrammes = db.prepare('SELECT id FROM programmes').all().map(p => p.id);
  const grant = db.prepare(`
    INSERT OR IGNORE INTO officer_programmes (officer_id, programme_id, granted_by_officer_id)
    VALUES (?, ?, ?)
  `);
  for (const pid of allProgrammes) grant.run(newId, pid, me.id);

  // Issue a setup token + email it.
  const officer = getOfficerRow(newId);
  const { plaintext } = issueToken({ officerId: newId, purpose: 'set_initial', issuedByOfficerId: me.id });
  let mailResult = null;
  try {
    mailResult = await sendPasswordSetupEmail({ officer, plaintextToken: plaintext, ttlHours: TOKEN_TTL_HOURS, isInitial: true });
  } catch (e) { console.error('Setup email failed:', e); }

  logAction({
    actor: me, action: 'officer.create',
    target_kind: 'officer', target_id: newId,
    after: officer,
    metadata: requestMeta(req, { setup_email_sent: Boolean(mailResult && mailResult.ok) })
  });
  res.status(201).json({
    officer: { ...officer, is_admin: Boolean(officer.is_admin), is_active: Boolean(officer.is_active) },
    setup_email: mailResult ? { delivered_via: mailResult.delivered_via, message_id: mailResult.message_id } : null
  });
});

app.patch('/api/admin/officers/:id', requireOfficer, requireAdmin, (req, res) => {
  const me = req.session.officer;
  const id = parseInt(req.params.id, 10);
  const before = getOfficerRow(id);
  if (!before) return res.status(404).json({ error: 'Not found' });

  // Can't deactivate or demote yourself — protects against locking everyone out.
  if (id === me.id && (req.body.is_admin === false || req.body.is_active === false)) {
    return res.status(400).json({ error: "You can't change your own admin or active status. Ask another admin." });
  }

  const fields = ['name', 'email', 'ministry', 'role', 'is_admin', 'is_active'];
  const sets = [];
  const params = [];
  for (const f of fields) {
    if (Object.prototype.hasOwnProperty.call(req.body || {}, f)) {
      let v = req.body[f];
      if (f === 'is_admin' || f === 'is_active') v = v ? 1 : 0;
      sets.push(`${f} = ?`);
      params.push(v);
    }
  }
  if (sets.length === 0) return res.status(400).json({ error: 'No fields to update' });
  params.push(id);
  db.prepare(`UPDATE officers SET ${sets.join(', ')} WHERE id = ?`).run(...params);

  const after = getOfficerRow(id);
  logAction({
    actor: me,
    action: after.is_active === 0 && before.is_active === 1 ? 'officer.deactivate' : 'officer.update',
    target_kind: 'officer', target_id: id,
    before, after,
    metadata: requestMeta(req)
  });
  res.json({ officer: { ...after, is_admin: Boolean(after.is_admin), is_active: Boolean(after.is_active) } });
});

app.post('/api/admin/officers/:id/password-reset', requireOfficer, requireAdmin, async (req, res) => {
  const me = req.session.officer;
  const id = parseInt(req.params.id, 10);
  const officer = getOfficerRow(id);
  if (!officer) return res.status(404).json({ error: 'Not found' });

  const { plaintext } = issueToken({ officerId: id, purpose: 'reset', issuedByOfficerId: me.id });
  let mailResult = null;
  try {
    mailResult = await sendPasswordSetupEmail({ officer, plaintextToken: plaintext, ttlHours: TOKEN_TTL_HOURS, isInitial: false });
  } catch (e) { console.error('Reset email failed:', e); }

  logAction({
    actor: me,
    action: 'officer.password_reset',
    target_kind: 'officer', target_id: id,
    metadata: requestMeta(req, { target_email: officer.email, email_sent: Boolean(mailResult && mailResult.ok) })
  });
  res.json({
    ok: true,
    email_sent_to: officer.email,
    delivered_via: mailResult ? mailResult.delivered_via : null,
    expires_in_hours: TOKEN_TTL_HOURS
  });
});

app.get('/api/admin/officers/:id/programmes', requireOfficer, requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const officer = getOfficerRow(id);
  if (!officer) return res.status(404).json({ error: 'Not found' });
  const assigned = listProgrammesForOfficer(id);
  const all = db.prepare('SELECT id, code, name FROM programmes ORDER BY name').all();
  const assignedSet = new Set(assigned.map(p => p.id));
  res.json({
    officer_id: id,
    programmes: all.map(p => ({ ...p, assigned: assignedSet.has(p.id) }))
  });
});

app.put('/api/admin/officers/:id/programmes', requireOfficer, requireAdmin, (req, res) => {
  const me = req.session.officer;
  const id = parseInt(req.params.id, 10);
  const officer = getOfficerRow(id);
  if (!officer) return res.status(404).json({ error: 'Not found' });
  const { programme_ids } = req.body || {};
  if (!Array.isArray(programme_ids)) return res.status(400).json({ error: 'programme_ids array required' });

  const before = listProgrammesForOfficer(id).map(p => p.id);
  const txn = db.transaction(() => {
    db.prepare('DELETE FROM officer_programmes WHERE officer_id = ?').run(id);
    const ins = db.prepare(`
      INSERT OR IGNORE INTO officer_programmes (officer_id, programme_id, granted_by_officer_id)
      VALUES (?, ?, ?)
    `);
    for (const pid of programme_ids) ins.run(id, Number(pid), me.id);
  });
  txn();
  const after = listProgrammesForOfficer(id).map(p => p.id);

  logAction({
    actor: me,
    action: 'officer.programmes_update',
    target_kind: 'officer', target_id: id,
    before: { programme_ids: before },
    after:  { programme_ids: after },
    metadata: requestMeta(req)
  });
  res.json({ programme_ids: after });
});

/* =========================================================
   Admin API — Programme management
   ========================================================= */

function getProgrammeRow(id) {
  return db.prepare(`
    SELECT id, code, name, ministry, default_sla_days, allowed_statuses,
           contact_email, contact_phone,
           accepting_applications, closed_at
    FROM programmes WHERE id = ?
  `).get(id);
}

const STATUS_TAXONOMY = ['received','under_review','action_needed','approved','rejected','completed'];

app.get('/api/admin/programmes', requireOfficer, requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT p.id, p.code, p.name, p.ministry, p.default_sla_days, p.allowed_statuses,
           p.contact_email, p.contact_phone,
           p.accepting_applications, p.closed_at,
           (SELECT COUNT(*) FROM applications a WHERE a.programme_id = p.id) AS application_count,
           (SELECT COUNT(*) FROM applications a WHERE a.programme_id = p.id AND a.current_status NOT IN ('completed','rejected')) AS open_count
    FROM programmes p
    ORDER BY p.name
  `).all();
  res.json({
    programmes: rows.map(p => ({
      ...p,
      allowed_statuses: safeJson(p.allowed_statuses, STATUS_TAXONOMY),
      accepting_applications: Boolean(p.accepting_applications)
    }))
  });
});

app.post('/api/admin/programmes', requireOfficer, requireAdmin, (req, res) => {
  const me = req.session.officer;
  const { code, name, ministry, default_sla_days, contact_email, contact_phone, accepting_applications } = req.body || {};
  if (!code || !/^[A-Z][A-Z0-9_-]{1,15}$/.test(code)) {
    return res.status(400).json({ error: 'code required (uppercase, 2-16 chars, letters/digits/_-)' });
  }
  if (!name || !ministry) return res.status(400).json({ error: 'name and ministry required' });
  const exists = db.prepare('SELECT 1 FROM programmes WHERE code = ?').get(code);
  if (exists) return res.status(409).json({ error: 'Programme code already in use' });

  const result = db.prepare(`
    INSERT INTO programmes (code, name, ministry, default_sla_days, allowed_statuses,
                            contact_email, contact_phone, accepting_applications)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(code, name.trim(), ministry.trim(),
         Number(default_sla_days) || 14,
         JSON.stringify(STATUS_TAXONOMY),
         contact_email || null, contact_phone || null,
         accepting_applications === false ? 0 : 1);
  const newId = result.lastInsertRowid;

  // Auto-grant every active officer access to the new programme.
  const officers = db.prepare('SELECT id FROM officers WHERE is_active = 1').all().map(o => o.id);
  const grant = db.prepare(`
    INSERT OR IGNORE INTO officer_programmes (officer_id, programme_id, granted_by_officer_id)
    VALUES (?, ?, ?)
  `);
  for (const oid of officers) grant.run(oid, newId, me.id);

  const after = getProgrammeRow(newId);
  logAction({
    actor: me, action: 'programme.create',
    target_kind: 'programme', target_id: newId,
    after,
    metadata: requestMeta(req)
  });
  res.status(201).json({
    programme: { ...after, allowed_statuses: safeJson(after.allowed_statuses, STATUS_TAXONOMY), accepting_applications: Boolean(after.accepting_applications) }
  });
});

app.patch('/api/admin/programmes/:id', requireOfficer, requireAdmin, (req, res) => {
  const me = req.session.officer;
  const id = parseInt(req.params.id, 10);
  const before = getProgrammeRow(id);
  if (!before) return res.status(404).json({ error: 'Not found' });

  const fields = ['name', 'ministry', 'default_sla_days', 'contact_email', 'contact_phone', 'accepting_applications'];
  const sets = [];
  const params = [];
  for (const f of fields) {
    if (Object.prototype.hasOwnProperty.call(req.body || {}, f)) {
      let v = req.body[f];
      if (f === 'accepting_applications') v = v ? 1 : 0;
      if (f === 'default_sla_days') v = Number(v) || 14;
      sets.push(`${f} = ?`);
      params.push(v);
    }
  }
  if (sets.length === 0) return res.status(400).json({ error: 'No fields to update' });

  // Track when the programme was most recently closed (for the dashboard's "since closed" line).
  if (Object.prototype.hasOwnProperty.call(req.body || {}, 'accepting_applications')
      && before.accepting_applications && !req.body.accepting_applications) {
    sets.push('closed_at = datetime(\'now\')');
  } else if (Object.prototype.hasOwnProperty.call(req.body || {}, 'accepting_applications')
      && !before.accepting_applications && req.body.accepting_applications) {
    sets.push('closed_at = NULL');
  }

  params.push(id);
  db.prepare(`UPDATE programmes SET ${sets.join(', ')} WHERE id = ?`).run(...params);
  const after = getProgrammeRow(id);

  const acceptingChanged = before.accepting_applications !== after.accepting_applications;
  logAction({
    actor: me,
    action: acceptingChanged ? 'programme.toggle_accepting' : 'programme.update',
    target_kind: 'programme', target_id: id,
    before, after,
    metadata: requestMeta(req)
  });
  res.json({
    programme: { ...after, allowed_statuses: safeJson(after.allowed_statuses, STATUS_TAXONOMY), accepting_applications: Boolean(after.accepting_applications) }
  });
});

/* =========================================================
   Admin API — Dashboard metrics
   ========================================================= */

app.get('/api/admin/dashboard', requireOfficer, requireAdmin, (req, res) => {
  // High-level counts.
  const totals = db.prepare(`
    SELECT
      COUNT(*) AS total_applications,
      SUM(CASE WHEN current_status NOT IN ('completed','rejected') THEN 1 ELSE 0 END) AS open_count,
      SUM(CASE WHEN current_status = 'completed' THEN 1 ELSE 0 END) AS completed_count,
      SUM(CASE WHEN current_status = 'rejected' THEN 1 ELSE 0 END) AS rejected_count,
      SUM(CASE WHEN flagged_after_close = 1 THEN 1 ELSE 0 END) AS flagged_count
    FROM applications
  `).get();

  const byStatus = db.prepare(`
    SELECT current_status AS status, COUNT(*) AS n
    FROM applications GROUP BY current_status
  `).all();

  // Time-to-completion: from the FIRST 'received' status_event to the FIRST
  // 'completed' status_event. SQLite has julianday() for date arithmetic.
  const completionRowsSql = `
    SELECT a.programme_id,
           p.code AS programme_code,
           p.name AS programme_name,
           (julianday(comp.created_at) - julianday(rec.created_at)) * 1.0 AS days
    FROM applications a
    JOIN programmes p ON p.id = a.programme_id
    JOIN (
      SELECT application_id, MIN(created_at) AS created_at
      FROM status_events WHERE status = 'received'
      GROUP BY application_id
    ) rec ON rec.application_id = a.id
    JOIN (
      SELECT application_id, MIN(created_at) AS created_at
      FROM status_events WHERE status = 'completed'
      GROUP BY application_id
    ) comp ON comp.application_id = a.id
    WHERE a.current_status = 'completed'
  `;
  const completedRows = db.prepare(completionRowsSql).all();

  const overall = computeStats(completedRows.map(r => r.days));

  // Per programme.
  const perProgrammeMap = {};
  for (const r of completedRows) {
    const k = r.programme_id;
    if (!perProgrammeMap[k]) perProgrammeMap[k] = { programme_id: k, programme_code: r.programme_code, programme_name: r.programme_name, durations: [] };
    perProgrammeMap[k].durations.push(r.days);
  }
  const perProgrammeStats = Object.values(perProgrammeMap).map(p => ({
    programme_id: p.programme_id,
    programme_code: p.programme_code,
    programme_name: p.programme_name,
    ...computeStats(p.durations)
  }));

  // Programmes with no completions yet, so the table is complete.
  const allProgrammes = db.prepare('SELECT id, code, name FROM programmes').all();
  const seen = new Set(perProgrammeStats.map(p => p.programme_id));
  for (const p of allProgrammes) {
    if (!seen.has(p.id)) {
      perProgrammeStats.push({
        programme_id: p.id,
        programme_code: p.code,
        programme_name: p.name,
        count: 0, mean_days: null, median_days: null, p90_days: null, min_days: null, max_days: null
      });
    }
  }
  perProgrammeStats.sort((a, b) => a.programme_name.localeCompare(b.programme_name));

  // Per-officer caseload (active workload, open only).
  const officerLoad = db.prepare(`
    SELECT o.id AS officer_id, o.name AS officer_name,
           SUM(CASE WHEN a.current_status NOT IN ('completed','rejected') THEN 1 ELSE 0 END) AS open_count,
           COUNT(a.id) AS total_count
    FROM officers o
    LEFT JOIN applications a ON a.assigned_officer_id = o.id
    WHERE o.is_active = 1
    GROUP BY o.id
    ORDER BY open_count DESC, o.name
  `).all();

  res.json({
    totals,
    by_status: byStatus,
    time_to_completion: { overall, per_programme: perProgrammeStats },
    officer_caseload: officerLoad,
    generated_at: new Date().toISOString()
  });
});

/** Compute mean/median/p90/min/max from an array of numbers. Returns null
 *  fields when the array is empty. */
function computeStats(values) {
  if (!values || values.length === 0) return { count: 0, mean_days: null, median_days: null, p90_days: null, min_days: null, max_days: null };
  const sorted = values.slice().sort((a, b) => a - b);
  const n = sorted.length;
  const mean = sorted.reduce((s, v) => s + v, 0) / n;
  const median = n % 2 ? sorted[(n - 1) / 2] : (sorted[n / 2 - 1] + sorted[n / 2]) / 2;
  const p90 = sorted[Math.min(n - 1, Math.floor(n * 0.9))];
  return {
    count: n,
    mean_days:   round1(mean),
    median_days: round1(median),
    p90_days:    round1(p90),
    min_days:    round1(sorted[0]),
    max_days:    round1(sorted[n - 1])
  };
}
function round1(x) { return Math.round(x * 10) / 10; }

/* =========================================================
   Admin API — Audit log
   ========================================================= */

app.get('/api/admin/audit-log', requireOfficer, requireAdmin, (req, res) => {
  const { limit, before, action, target_kind, target_id } = req.query;
  const rows = listAuditLog({
    limit: limit ? Number(limit) : 50,
    before: before ? Number(before) : null,
    action: action || null,
    target_kind: target_kind || null,
    target_id: target_id ? Number(target_id) : null
  });
  res.json({ entries: rows });
});

/* =========================================================
   Helpers
   ========================================================= */

function safeJson(s, fallback = null) {
  if (!s) return fallback;
  try { return JSON.parse(s); } catch (_) { return fallback; }
}

/* =========================================================
   Boot
   ========================================================= */

const programmesCount = db.prepare('SELECT COUNT(*) AS n FROM programmes').get().n;
if (programmesCount === 0) {
  console.log('No programmes found. Run "npm run seed" first.');
}

app.listen(PORT, () => {
  console.log(`\nGovBB Application Tracker pilot`);
  console.log(`  http://localhost:${PORT}/                  citizen tracker`);
  console.log(`  http://localhost:${PORT}/submit-test       demo form submission`);
  console.log(`  http://localhost:${PORT}/officer/login     officer console (andrea / andrea)`);
  console.log(`  Emails written to:  ./mail-out/`);
  console.log(`  Database:           ./data/tracker.db`);
});
