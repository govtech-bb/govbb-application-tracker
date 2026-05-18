const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const lusca = require('lusca');
const rateLimit = require('express-rate-limit');

const {
  pool,
  initDb,
  insertStatusEvent,
  getApplicationByCode,
  getApplicationById,
  listApplicationsForOfficer,
  listDeletedApplications,
  listProgrammesForOfficer,
  officerCanAccessApplication,
  getPendingAction,
  recordActionResponse
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
const APP_MODE = (process.env.APP_MODE || 'all').toLowerCase(); // 'public', 'admin', or 'all'
const SERVE_PUBLIC = APP_MODE === 'public' || APP_MODE === 'all';
const SERVE_ADMIN = APP_MODE === 'admin' || APP_MODE === 'all';

app.set('trust proxy', 1);

if (IS_PROD && !process.env.SESSION_SECRET) {
  console.error('FATAL: SESSION_SECRET must be set in production.');
  process.exit(1);
}

app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  store: IS_PROD ? new pgSession({ pool, createTableIfMissing: true }) : undefined,
  secret: process.env.SESSION_SECRET || 'dev-only-pilot-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PROD,
    maxAge: 1000 * 60 * 60 * 8
  }
}));

const csrfMiddleware = lusca.csrf({ header: 'x-csrf-token', angular: false });
const CSRF_EXEMPT = new Set(['/api/set-password']);
const CSRF_EXEMPT_PREFIX = ['/api/webhooks/', '/api/applications/'];
app.use((req, res, next) => {
  if (CSRF_EXEMPT.has(req.path)) return next();
  if (CSRF_EXEMPT_PREFIX.some(p => req.path.startsWith(p))) return next();
  csrfMiddleware(req, res, next);
});

app.get('/api/csrf-token', (req, res) => {
  res.json({ token: res.locals._csrf });
});

/* =========================================================
   Rate limiters.
   ========================================================= */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' }
});

const passwordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Try again later.' }
});

const webhookLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Rate limit exceeded. Try again later.' }
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Try again later.' }
});

app.use('/api/', apiLimiter);

const pageLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
});

/* =========================================================
   File-upload setup.
   Disk-based uploads are disabled — will be replaced with S3.
   ========================================================= */
const FILE_UPLOADS_ENABLED = false;

app.get('/healthz', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

app.get('/healthz/email', (req, res) => {
  const cfg = emailConfig();
  res.json({
    ok: cfg.resend_api_key_set,
    config: cfg,
    instructions: cfg.resend_api_key_set
      ? 'Looks configured. POST /api/officer/test-email with {"to":"you@example.com"} to send a real test (officer auth required).'
      : 'RESEND_API_KEY is not set — emails will land on disk only. Set it in Render env vars to enable real send.'
  });
});

app.post('/api/officer/test-email', requireOfficer, async (req, res) => {
  const { to } = req.body || {};
  const targetEmail = (to || '').trim() || req.session.officer.email || null;
  const result = await sendTestEmail({
    to: targetEmail,
    sentByOfficer: req.session.officer.username
  });
  await logAction({
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

if (SERVE_PUBLIC) {
  app.get('/', pageLimiter, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
  app.get('/track', pageLimiter, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
  app.get('/track/:code', pageLimiter, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
  app.get('/chat', pageLimiter, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
  app.get('/confirmation/:code', pageLimiter, (req, res) => res.sendFile(path.join(__dirname, 'confirmation.html')));
}

if (SERVE_ADMIN) {
  if (!SERVE_PUBLIC) app.get('/', pageLimiter, (req, res) => res.redirect('/officer/login'));
  app.get('/submit-test', pageLimiter, (req, res) => res.sendFile(path.join(__dirname, 'submit-test.html')));
  app.get('/officer/login', pageLimiter, (req, res) => res.sendFile(path.join(__dirname, 'officer-login.html')));
  app.get('/officer', pageLimiter, requireOfficer, (req, res) => res.sendFile(path.join(__dirname, 'officer.html')));
  app.get('/set-password/:token', pageLimiter, (req, res) => res.sendFile(path.join(__dirname, 'set-password.html')));
}

/* =========================================================
   Password setup / reset (token-protected, admin side)
   ========================================================= */

if (SERVE_ADMIN) {
  app.get('/api/password-rules', (req, res) => {
    res.json({ rules: PASSWORD_RULES, ttl_hours: TOKEN_TTL_HOURS });
  });

  app.get('/api/password-token/:token', passwordLimiter, async (req, res) => {
    const t = await findValidToken(req.params.token);
    if (!t || t.error) return res.status(400).json({ error: errorMessage(t && t.error), code: (t && t.error) || 'unknown' });
    res.json({
      valid: true,
      purpose: t.purpose,
      officer: { name: t.officer.name, email: t.officer.email },
      expires_at: t.expires_at
    });
  });

  app.post('/api/set-password', passwordLimiter, async (req, res) => {
    const { token, password } = req.body || {};
    if (!token || !password) return res.status(400).json({ error: 'token and password required' });

    const t = await findValidToken(token);
    if (!t || t.error) {
      await logAction({ action: 'password.set_fail', metadata: requestMeta(req, { reason: t && t.error || 'unknown' }) });
      return res.status(400).json({ error: errorMessage(t && t.error), code: (t && t.error) || 'unknown' });
    }

    const v = validatePassword(password, { email: t.officer.email });
    if (!v.ok) return res.status(400).json({ error: v.errors[0], errors: v.errors });

    await consumeTokenAndSetPassword(t.id, t.officer_id, hashPassword(password));
    await logAction({
      action: 'password.set_success',
      target_kind: 'officer', target_id: t.officer_id,
      metadata: requestMeta(req, { purpose: t.purpose, officer_email: t.officer.email })
    });
    res.json({ ok: true, redirect_to: '/officer/login' });
  });
}

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

if (SERVE_ADMIN) {
  app.post('/api/officer/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const officer = await authenticateOfficer(username, password);
    if (officer && officer._inactive) {
      await logAction({ action: 'login.fail', metadata: requestMeta(req, { username, reason: 'inactive' }) });
      return res.status(403).json({ error: 'This account has been deactivated. Contact your admin.' });
    }
    if (!officer) {
      await logAction({ action: 'login.fail', metadata: requestMeta(req, { username, reason: 'bad_credentials' }) });
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    req.session.officer = officer;
    await logAction({
      actor: officer,
      action: 'login.success',
      target_kind: 'officer',
      target_id: officer.id,
      metadata: requestMeta(req)
    });
    res.json({ officer });
  });

  app.post('/api/officer/logout', async (req, res) => {
    const actor = req.session.officer;
    if (actor) {
      await logAction({
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
}

app.get('/api/programmes', async (req, res) => {
  const { rows } = await pool.query(`
    SELECT code, name, ministry, default_sla_days, contact_email, contact_phone,
           accepting_applications
    FROM programmes
    WHERE accepting_applications = 1
    ORDER BY name
  `);
  res.json({ programmes: rows });
});

/* =========================================================
   Public API
   ========================================================= */

if (SERVE_PUBLIC) {

app.get('/api/sample-codes', async (req, res) => {
  if (IS_PROD) return res.status(404).json({ error: 'Not found' });
  const { rows } = await pool.query(`
    SELECT a.code, p.name AS programme_name, ap.name AS applicant_name, a.current_status
    FROM applications a
    JOIN programmes p ON p.id = a.programme_id
    JOIN applicants ap ON ap.id = a.applicant_id
    ORDER BY a.created_at DESC
    LIMIT 12
  `);
  res.json({ codes: rows });
});

app.get('/api/applications/:code', async (req, res) => {
  const application = await getApplicationByCode(req.params.code.toUpperCase().trim());
  if (!application) return res.status(404).json({ error: 'Application not found' });
  const pending = await getPendingAction(application.id);
  res.json({
    application: {
      code: application.code,
      programme_code: application.programme_code,
      programme_name: application.programme_name,
      ministry: application.ministry,
      contact_email: application.contact_email,
      contact_phone: application.contact_phone,
      default_sla_days: application.default_sla_days,
      applicant_name: application.applicant_name,
      submitted_at: application.created_at,
      current_status: application.current_status,
      current_status_at: application.current_status_at,
      assigned_officer_name: application.assigned_officer_name,
      pending_action: pending ? {
        event_id: pending.id,
        type: pending.action_type,
        label: pending.action_label,
        requested_at: pending.created_at
      } : null,
      timeline: application.timeline
        .filter(t => (t.citizen_message && t.citizen_message.trim()) || t.action_response_at)
        .map(t => ({
          status: t.status,
          message: t.citizen_message,
          at: t.created_at,
          action_type: t.action_type || null,
          action_label: t.action_label || null,
          action_response: t.action_response || null,
          action_response_at: t.action_response_at || null,
          uploads: (t.uploads || []).map(u => ({
            original_filename: u.original_filename,
            mime_type: u.mime_type,
            size_bytes: u.size_bytes
          }))
        }))
    }
  });
});

/* =========================================================
   Citizen response to an "action needed" request.
   ========================================================= */

app.post('/api/applications/:code/respond', async (req, res) => {
  const code = (req.params.code || '').toUpperCase();
  const application = await getApplicationByCode(code);
  if (!application) return res.status(404).json({ error: 'Application not found' });
  const pending = await getPendingAction(application.id);
  if (!pending) return res.status(400).json({ error: 'There is no outstanding request on this application.' });

  if (pending.action_type === 'file') {
    if (!FILE_UPLOADS_ENABLED) {
      return res.status(501).json({ error: 'File uploads are temporarily unavailable. Please try again later.' });
    }
  }

  if (pending.action_type !== 'file') {
    const body = req.body || {};
    let responseText = null;
    if (pending.action_type === 'confirmation') {
      if (body.confirmed !== true) {
        return res.status(400).json({ error: 'You must tick the confirmation to submit.' });
      }
      responseText = 'Confirmed';
    } else {
      const raw = String(body.response || '').trim();
      if (!raw) return res.status(400).json({ error: 'A response is required.' });
      const limit = pending.action_type === 'textarea' ? 4000 : 500;
      if (raw.length > limit) return res.status(400).json({ error: `Response too long (max ${limit} characters).` });
      responseText = raw;
    }
    await recordActionResponse({
      event_id: pending.id,
      application_id: application.id,
      response_text: responseText,
      file: null
    });
    await finaliseCitizenResponse({ application, pending, req, res, summary: responseText.slice(0, 80) });
  }
});

async function finaliseCitizenResponse({ application, pending, req, res, summary }) {
  await insertStatusEvent({
    application_id: application.id,
    status: 'under_review',
    citizen_message: 'Your response has been received and is being reviewed.',
    internal_note: `Citizen responded to action request: ${summary}`,
    by_officer_id: null
  });
  await logAction({
    actor: null,
    action: 'application.citizen_response',
    target_kind: 'application',
    target_id: application.id,
    metadata: requestMeta(req, { code: application.code, action_type: pending.action_type, summary })
  });
  const refreshed = await getApplicationByCode(application.code);
  const pendingNow = await getPendingAction(application.id);
  res.status(200).json({
    ok: true,
    application: {
      code: refreshed.code,
      current_status: refreshed.current_status,
      current_status_at: refreshed.current_status_at,
      pending_action: pendingNow ? {
        event_id: pendingNow.id,
        type: pendingNow.action_type,
        label: pendingNow.action_label,
        requested_at: pendingNow.created_at
      } : null
    }
  });
}

} // end SERVE_PUBLIC

/* =========================================================
   Officer-only download for citizen-uploaded files.
   ========================================================= */

if (SERVE_ADMIN) {

app.get('/api/officer/applications/:id/uploads/:upload_id', requireOfficer, async (req, res) => {
  if (!FILE_UPLOADS_ENABLED) {
    return res.status(501).json({ error: 'File downloads are temporarily unavailable.' });
  }
  const me = req.session.officer;
  const appId = parseInt(req.params.id, 10);
  const upId = parseInt(req.params.upload_id, 10);
  if (!(await officerCanAccessApplication(me.id, me.is_admin, appId))) {
    return res.status(403).json({ error: 'You do not have access to this application' });
  }
  const UPLOAD_DIR = process.env.UPLOAD_DIR
    || path.join(process.env.TRACKER_DATA_DIR || path.join(__dirname, 'data'), 'uploads');
  const { rows } = await pool.query(`
    SELECT id, application_id, original_filename, stored_filename, mime_type, size_bytes
    FROM uploads
    WHERE id = $1 AND application_id = $2
  `, [upId, appId]);
  const row = rows[0];
  if (!row) return res.status(404).json({ error: 'Upload not found' });
  const fullPath = path.resolve(UPLOAD_DIR, String(appId), row.stored_filename);
  if (!fullPath.startsWith(path.resolve(UPLOAD_DIR))) {
    return res.status(400).json({ error: 'Invalid file path' });
  }
  if (!fs.existsSync(fullPath)) return res.status(410).json({ error: 'File is no longer on disk' });

  res.setHeader('Content-Type', row.mime_type || 'application/octet-stream');
  res.setHeader('Content-Disposition',
    `inline; filename="${row.original_filename.replace(/"/g, '\\"')}"`);
  res.setHeader('Content-Length', row.size_bytes);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  fs.createReadStream(fullPath).pipe(res);

  logAction({
    actor: me,
    action: 'application.upload_view',
    target_kind: 'application', target_id: appId,
    metadata: requestMeta(req, { upload_id: upId, filename: row.original_filename })
  });
});

/* =========================================================
   Form intake webhook — secured with API key.
   ========================================================= */

const CODE_PATTERN = /^[A-Z][A-Z0-9_-]*-\d{4}-[A-Z0-9]{6,16}$/;

app.post('/api/webhooks/form-submitted', webhookLimiter, requireApiKey, async (req, res) => {
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

  const { rows: progRows } = await pool.query('SELECT * FROM programmes WHERE code = $1', [programme_code]);
  const programme = progRows[0];
  if (!programme) return res.status(404).json({ error: `Unknown programme: ${programme_code}` });

  const { rows: existingRows } = await pool.query(`
    SELECT a.id, a.code, a.programme_id, ap.email AS applicant_email
    FROM applications a JOIN applicants ap ON ap.id = a.applicant_id
    WHERE a.code = $1
  `, [code]);
  const existing = existingRows[0];
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

  const flaggedAfterClose = programme.accepting_applications ? 0 : 1;

  const { rows: appInsertRows } = await pool.query(`
    INSERT INTO applicants (name, email, phone) VALUES ($1, $2, $3) RETURNING id
  `, [applicant.name, applicant.email, applicant.phone || null]);
  const applicantId = appInsertRows[0].id;

  let applicationId;
  if (submittedSql) {
    const { rows: r } = await pool.query(`
      INSERT INTO applications (code, programme_id, applicant_id, current_status, current_status_at, form_data, flagged_after_close, created_at)
      VALUES ($1, $2, $3, 'received', $4, $5, $6, $7)
      RETURNING id
    `, [code, programme.id, applicantId, submittedSql, JSON.stringify(form_data || {}), flaggedAfterClose, submittedSql]);
    applicationId = r[0].id;
  } else {
    const { rows: r } = await pool.query(`
      INSERT INTO applications (code, programme_id, applicant_id, current_status, current_status_at, form_data, flagged_after_close)
      VALUES ($1, $2, $3, 'received', NOW(), $4, $5)
      RETURNING id
    `, [code, programme.id, applicantId, JSON.stringify(form_data || {}), flaggedAfterClose]);
    applicationId = r[0].id;
  }

  await insertStatusEvent({
    application_id: applicationId,
    status: 'received',
    citizen_message: 'Application received and acknowledged.',
    internal_note: flaggedAfterClose
      ? `Pushed via API by client #${req.apiClient.id} (${req.apiClient.name}). Flagged: programme is not accepting applications.`
      : `Pushed via API by client #${req.apiClient.id} (${req.apiClient.name}).`,
    by_officer_id: null
  });

  await logAction({
    actor: null,
    action: 'application.intake',
    target_kind: 'application',
    target_id: applicationId,
    after: { code, programme_code, flagged_after_close: flaggedAfterClose },
    metadata: requestMeta(req, { api_client: req.apiClient.name, applicant_email: applicant.email })
  });

  const fullApp = await getApplicationById(applicationId);
  sendSubmissionEmail(fullApp).catch(e => console.error('Submission email failed:', e));

  res.status(201).json({
    code,
    flagged_after_close: Boolean(flaggedAfterClose),
    tracker_url: `/track/${encodeURIComponent(code)}`,
    confirmation_url: `/confirmation/${encodeURIComponent(code)}`
  });
});

/* =========================================================
   Officer API — caseload
   ========================================================= */

app.get('/api/officer/applications', requireOfficer, async (req, res) => {
  const me = req.session.officer;
  res.json({ applications: await listApplicationsForOfficer(me.id, me.is_admin) });
});

app.get('/api/officer/applications/deleted', requireOfficer, async (req, res) => {
  const me = req.session.officer;
  if (!me.is_admin) return res.status(403).json({ error: 'Admin access required' });
  res.json({ applications: await listDeletedApplications() });
});

app.get('/api/officer/applications/:id', requireOfficer, async (req, res) => {
  const me = req.session.officer;
  const id = parseInt(req.params.id, 10);
  if (!(await officerCanAccessApplication(me.id, me.is_admin, id))) {
    return res.status(403).json({ error: 'You do not have access to this application' });
  }
  const application = await getApplicationById(id);
  if (!application) return res.status(404).json({ error: 'Not found' });
  res.json({ application });
});

app.patch('/api/officer/applications/:id', requireOfficer, async (req, res) => {
  const me = req.session.officer;
  const id = parseInt(req.params.id, 10);
  if (!(await officerCanAccessApplication(me.id, me.is_admin, id))) {
    return res.status(403).json({ error: 'You do not have access to this application' });
  }
  const before = await getApplicationById(id);
  if (!before) return res.status(404).json({ error: 'Not found' });

  const { status, citizen_message, internal_note, action_type, action_label } = req.body || {};
  if (!status) return res.status(400).json({ error: 'status required' });

  const { rows: progRows } = await pool.query('SELECT allowed_statuses FROM programmes WHERE id = $1', [before.programme_id]);
  const allowed = JSON.parse(progRows[0].allowed_statuses);
  if (!allowed.includes(status)) {
    return res.status(400).json({ error: `Status ${status} not allowed for this programme` });
  }

  const VALID_ACTION_TYPES = ['text', 'textarea', 'file', 'confirmation'];
  let cleanActionType = null;
  let cleanActionLabel = null;
  if (status === 'action_needed' && action_type) {
    if (!VALID_ACTION_TYPES.includes(action_type)) {
      return res.status(400).json({ error: `action_type must be one of ${VALID_ACTION_TYPES.join(', ')}` });
    }
    if (!action_label || !String(action_label).trim()) {
      return res.status(400).json({ error: 'action_label required when action_type is set' });
    }
    cleanActionType = action_type;
    cleanActionLabel = String(action_label).trim().slice(0, 500);
  }

  const defaults = {
    received: 'Application received.',
    under_review: 'An officer is now reviewing your application.',
    action_needed: cleanActionLabel || 'We need something from you. Please check your email.',
    approved: 'Decision: approved.',
    rejected: 'Decision: not approved.',
    completed: 'Your application is complete.'
  };
  const finalCitizenMessage = (citizen_message && citizen_message.trim()) || defaults[status] || 'Status updated.';

  await insertStatusEvent({
    application_id: id,
    status,
    citizen_message: finalCitizenMessage,
    internal_note: (internal_note && internal_note.trim()) || null,
    by_officer_id: me.id,
    action_type: cleanActionType,
    action_label: cleanActionLabel
  });

  await logAction({
    actor: me,
    action: 'application.status_change',
    target_kind: 'application',
    target_id: id,
    before: { status: before.current_status },
    after:  { status, citizen_message: finalCitizenMessage, internal_note: internal_note || null },
    metadata: requestMeta(req, { code: before.code })
  });

  const fullApp = await getApplicationById(id);
  const lastEvent = fullApp.timeline[fullApp.timeline.length - 1];
  sendStatusChangeEmail(fullApp, lastEvent).catch(e => console.error('Status email failed:', e));

  res.json({ application: await getApplicationById(id) });
});

app.post('/api/officer/applications/:id/assign-me', requireOfficer, async (req, res) => {
  const me = req.session.officer;
  const id = parseInt(req.params.id, 10);
  if (!(await officerCanAccessApplication(me.id, me.is_admin, id))) {
    return res.status(403).json({ error: 'You do not have access to this application' });
  }
  const before = await getApplicationById(id);
  if (!before) return res.status(404).json({ error: 'Not found' });

  await pool.query('UPDATE applications SET assigned_officer_id = $1 WHERE id = $2', [me.id, id]);

  await insertStatusEvent({
    application_id: id,
    status: before.current_status,
    citizen_message: null,
    internal_note: `Assigned to ${me.name}.`,
    by_officer_id: me.id
  });

  await logAction({
    actor: me,
    action: 'application.assign',
    target_kind: 'application',
    target_id: id,
    before: { assigned_officer_id: before.assigned_officer_id || null },
    after:  { assigned_officer_id: me.id },
    metadata: requestMeta(req, { code: before.code })
  });

  res.json({ application: await getApplicationById(id) });
});

app.delete('/api/officer/applications', requireOfficer, async (req, res) => {
  const me = req.session.officer;
  const { ids } = req.body || {};
  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: 'ids array required' });
  }
  if (ids.length > 50) {
    return res.status(400).json({ error: 'Maximum 50 applications per request' });
  }
  const parsed = ids.map(id => parseInt(id, 10)).filter(n => !isNaN(n));
  if (parsed.length === 0) {
    return res.status(400).json({ error: 'No valid ids provided' });
  }

  const deleted = [];
  const errors = [];

  for (const id of parsed) {
    if (!(await officerCanAccessApplication(me.id, me.is_admin, id))) {
      errors.push({ id, error: 'Access denied' });
      continue;
    }
    const app = await getApplicationById(id);
    if (!app) {
      errors.push({ id, error: 'Not found' });
      continue;
    }

    await pool.query('UPDATE applications SET deleted_at = NOW() WHERE id = $1', [id]);

    await logAction({
      actor: me,
      action: 'application.delete',
      target_kind: 'application',
      target_id: id,
      before: { status: app.current_status },
      after: { deleted: true },
      metadata: requestMeta(req, { code: app.code })
    });

    deleted.push({ id, code: app.code });
  }

  res.json({ deleted, errors });
});

app.post('/api/officer/applications/restore', requireOfficer, async (req, res) => {
  const me = req.session.officer;
  if (!me.is_admin) return res.status(403).json({ error: 'Admin access required' });
  const { ids } = req.body || {};
  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: 'ids array required' });
  }
  const parsed = ids.map(id => parseInt(id, 10)).filter(n => !isNaN(n));

  const restored = [];
  for (const id of parsed) {
    const { rows } = await pool.query(
      'UPDATE applications SET deleted_at = NULL WHERE id = $1 AND deleted_at IS NOT NULL RETURNING code', [id]
    );
    if (rows.length > 0) {
      await logAction({
        actor: me,
        action: 'application.restore',
        target_kind: 'application',
        target_id: id,
        before: { deleted: true },
        after: { deleted: false },
        metadata: requestMeta(req, { code: rows[0].code })
      });
      restored.push({ id, code: rows[0].code });
    }
  }
  res.json({ restored });
});

app.post('/api/officer/applications/purge', requireOfficer, async (req, res) => {
  const me = req.session.officer;
  if (!me.is_admin) return res.status(403).json({ error: 'Admin access required' });
  const { ids } = req.body || {};
  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: 'ids array required' });
  }
  const parsed = ids.map(id => parseInt(id, 10)).filter(n => !isNaN(n));

  const purged = [];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const id of parsed) {
      const { rows } = await client.query(
        'SELECT a.code, ap.name AS applicant_name, p.name AS programme_name FROM applications a JOIN applicants ap ON ap.id = a.applicant_id JOIN programmes p ON p.id = a.programme_id WHERE a.id = $1 AND a.deleted_at IS NOT NULL', [id]
      );
      if (rows.length === 0) continue;
      const snap = rows[0];

      await client.query('DELETE FROM uploads WHERE application_id = $1', [id]);
      await client.query('DELETE FROM notifications WHERE application_id = $1', [id]);
      await client.query('DELETE FROM status_events WHERE application_id = $1', [id]);
      await client.query('DELETE FROM applications WHERE id = $1', [id]);

      await logAction({
        actor: me,
        action: 'application.purge',
        target_kind: 'application',
        target_id: id,
        before: { code: snap.code, applicant: snap.applicant_name, programme: snap.programme_name },
        after: null,
        metadata: requestMeta(req, { code: snap.code })
      });
      purged.push({ id, code: snap.code });
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Purge failed:', e);
    return res.status(500).json({ error: 'Purge failed' });
  } finally {
    client.release();
  }
  res.json({ purged });
});

/* =========================================================
   Admin API — Officer management
   ========================================================= */

async function getOfficerRow(id) {
  const { rows } = await pool.query(`
    SELECT id, username, name, email, ministry, role, is_admin, is_active, created_at
    FROM officers
    WHERE id = $1
  `, [id]);
  return rows[0] || null;
}

app.get('/api/admin/officers', requireOfficer, requireAdmin, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT id, username, name, email, ministry, role,
           is_admin, is_active, created_at,
           (SELECT COUNT(*) FROM officer_programmes op WHERE op.officer_id = officers.id) AS programme_count
    FROM officers
    ORDER BY name
  `);
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
  const { rows: existingRows } = await pool.query(
    'SELECT 1 FROM officers WHERE username = $1 OR email = $2', [cleanEmail, cleanEmail]
  );
  if (existingRows.length > 0) return res.status(409).json({ error: 'An officer with this email already exists' });

  const placeholderHash = hashPassword(crypto.randomBytes(24).toString('base64'));
  const { rows: insertRows } = await pool.query(`
    INSERT INTO officers (username, password_hash, name, email, ministry, role, is_admin, is_active)
    VALUES ($1, $2, $3, $4, $5, $6, $7, 1)
    RETURNING id
  `, [cleanEmail, placeholderHash, name.trim(), cleanEmail, ministry.trim(), role.trim(), is_admin ? 1 : 0]);
  const newId = insertRows[0].id;

  const { rows: allProgrammes } = await pool.query('SELECT id FROM programmes');
  for (const p of allProgrammes) {
    await pool.query(`
      INSERT INTO officer_programmes (officer_id, programme_id, granted_by_officer_id)
      VALUES ($1, $2, $3)
      ON CONFLICT DO NOTHING
    `, [newId, p.id, me.id]);
  }

  const officer = await getOfficerRow(newId);
  const { plaintext } = await issueToken({ officerId: newId, purpose: 'set_initial', issuedByOfficerId: me.id });
  let mailResult = null;
  try {
    mailResult = await sendPasswordSetupEmail({ officer, plaintextToken: plaintext, ttlHours: TOKEN_TTL_HOURS, isInitial: true });
  } catch (e) { console.error('Setup email failed:', e); }

  await logAction({
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

app.patch('/api/admin/officers/:id', requireOfficer, requireAdmin, async (req, res) => {
  const me = req.session.officer;
  const id = parseInt(req.params.id, 10);
  const before = await getOfficerRow(id);
  if (!before) return res.status(404).json({ error: 'Not found' });

  if (id === me.id && (req.body.is_admin === false || req.body.is_active === false)) {
    return res.status(400).json({ error: "You can't change your own admin or active status. Ask another admin." });
  }

  const fields = ['name', 'email', 'ministry', 'role', 'is_admin', 'is_active'];
  const sets = [];
  const params = [];
  let n = 1;
  for (const f of fields) {
    if (Object.prototype.hasOwnProperty.call(req.body || {}, f)) {
      let v = req.body[f];
      if (f === 'is_admin' || f === 'is_active') v = v ? 1 : 0;
      sets.push(`${f} = $${n++}`);
      params.push(v);
    }
  }
  if (sets.length === 0) return res.status(400).json({ error: 'No fields to update' });
  params.push(id);
  await pool.query(`UPDATE officers SET ${sets.join(', ')} WHERE id = $${n}`, params);

  const after = await getOfficerRow(id);
  await logAction({
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
  const officer = await getOfficerRow(id);
  if (!officer) return res.status(404).json({ error: 'Not found' });

  const { plaintext } = await issueToken({ officerId: id, purpose: 'reset', issuedByOfficerId: me.id });
  let mailResult = null;
  try {
    mailResult = await sendPasswordSetupEmail({ officer, plaintextToken: plaintext, ttlHours: TOKEN_TTL_HOURS, isInitial: false });
  } catch (e) { console.error('Reset email failed:', e); }

  await logAction({
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

app.get('/api/admin/officers/:id/programmes', requireOfficer, requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const officer = await getOfficerRow(id);
  if (!officer) return res.status(404).json({ error: 'Not found' });
  const assigned = await listProgrammesForOfficer(id);
  const { rows: all } = await pool.query('SELECT id, code, name FROM programmes ORDER BY name');
  const assignedSet = new Set(assigned.map(p => p.id));
  res.json({
    officer_id: id,
    programmes: all.map(p => ({ ...p, assigned: assignedSet.has(p.id) }))
  });
});

app.put('/api/admin/officers/:id/programmes', requireOfficer, requireAdmin, async (req, res) => {
  const me = req.session.officer;
  const id = parseInt(req.params.id, 10);
  const officer = await getOfficerRow(id);
  if (!officer) return res.status(404).json({ error: 'Not found' });
  const { programme_ids } = req.body || {};
  if (!Array.isArray(programme_ids)) return res.status(400).json({ error: 'programme_ids array required' });

  const beforeList = (await listProgrammesForOfficer(id)).map(p => p.id);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM officer_programmes WHERE officer_id = $1', [id]);
    for (const pid of programme_ids) {
      await client.query(`
        INSERT INTO officer_programmes (officer_id, programme_id, granted_by_officer_id)
        VALUES ($1, $2, $3)
        ON CONFLICT DO NOTHING
      `, [id, Number(pid), me.id]);
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }

  const afterList = (await listProgrammesForOfficer(id)).map(p => p.id);
  await logAction({
    actor: me,
    action: 'officer.programmes_update',
    target_kind: 'officer', target_id: id,
    before: { programme_ids: beforeList },
    after:  { programme_ids: afterList },
    metadata: requestMeta(req)
  });
  res.json({ programme_ids: afterList });
});

/* =========================================================
   Admin API — Programme management
   ========================================================= */

async function getProgrammeRow(id) {
  const { rows } = await pool.query(`
    SELECT id, code, name, ministry, default_sla_days, allowed_statuses,
           contact_email, contact_phone,
           accepting_applications, closed_at
    FROM programmes WHERE id = $1
  `, [id]);
  return rows[0] || null;
}

const STATUS_TAXONOMY = ['received','under_review','action_needed','approved','rejected','completed'];

app.get('/api/admin/programmes', requireOfficer, requireAdmin, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT p.id, p.code, p.name, p.ministry, p.default_sla_days, p.allowed_statuses,
           p.contact_email, p.contact_phone,
           p.accepting_applications, p.closed_at,
           (SELECT COUNT(*) FROM applications a WHERE a.programme_id = p.id) AS application_count,
           (SELECT COUNT(*) FROM applications a WHERE a.programme_id = p.id AND a.current_status NOT IN ('completed','rejected')) AS open_count
    FROM programmes p
    ORDER BY p.name
  `);
  res.json({
    programmes: rows.map(p => ({
      ...p,
      allowed_statuses: safeJson(p.allowed_statuses, STATUS_TAXONOMY),
      accepting_applications: Boolean(p.accepting_applications)
    }))
  });
});

app.post('/api/admin/programmes', requireOfficer, requireAdmin, async (req, res) => {
  const me = req.session.officer;
  const { code, name, ministry, default_sla_days, contact_email, contact_phone, accepting_applications } = req.body || {};
  if (!code || !/^[A-Z][A-Z0-9_-]{1,15}$/.test(code)) {
    return res.status(400).json({ error: 'code required (uppercase, 2-16 chars, letters/digits/_-)' });
  }
  if (!name || !ministry) return res.status(400).json({ error: 'name and ministry required' });
  const { rows: existRows } = await pool.query('SELECT 1 FROM programmes WHERE code = $1', [code]);
  if (existRows.length > 0) return res.status(409).json({ error: 'Programme code already in use' });

  const { rows: insertRows } = await pool.query(`
    INSERT INTO programmes (code, name, ministry, default_sla_days, allowed_statuses,
                            contact_email, contact_phone, accepting_applications)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    RETURNING id
  `, [code, name.trim(), ministry.trim(),
      Number(default_sla_days) || 14,
      JSON.stringify(STATUS_TAXONOMY),
      contact_email || null, contact_phone || null,
      accepting_applications === false ? 0 : 1]);
  const newId = insertRows[0].id;

  const { rows: officers } = await pool.query('SELECT id FROM officers WHERE is_active = 1');
  for (const o of officers) {
    await pool.query(`
      INSERT INTO officer_programmes (officer_id, programme_id, granted_by_officer_id)
      VALUES ($1, $2, $3)
      ON CONFLICT DO NOTHING
    `, [o.id, newId, me.id]);
  }

  const after = await getProgrammeRow(newId);
  await logAction({
    actor: me, action: 'programme.create',
    target_kind: 'programme', target_id: newId,
    after,
    metadata: requestMeta(req)
  });
  res.status(201).json({
    programme: { ...after, allowed_statuses: safeJson(after.allowed_statuses, STATUS_TAXONOMY), accepting_applications: Boolean(after.accepting_applications) }
  });
});

app.patch('/api/admin/programmes/:id', requireOfficer, requireAdmin, async (req, res) => {
  const me = req.session.officer;
  const id = parseInt(req.params.id, 10);
  const before = await getProgrammeRow(id);
  if (!before) return res.status(404).json({ error: 'Not found' });

  const fields = ['name', 'ministry', 'default_sla_days', 'contact_email', 'contact_phone', 'accepting_applications'];
  const sets = [];
  const params = [];
  let n = 1;
  for (const f of fields) {
    if (Object.prototype.hasOwnProperty.call(req.body || {}, f)) {
      let v = req.body[f];
      if (f === 'accepting_applications') v = v ? 1 : 0;
      if (f === 'default_sla_days') v = Number(v) || 14;
      sets.push(`${f} = $${n++}`);
      params.push(v);
    }
  }
  if (sets.length === 0) return res.status(400).json({ error: 'No fields to update' });

  if (Object.prototype.hasOwnProperty.call(req.body || {}, 'accepting_applications')
      && before.accepting_applications && !req.body.accepting_applications) {
    sets.push('closed_at = NOW()');
  } else if (Object.prototype.hasOwnProperty.call(req.body || {}, 'accepting_applications')
      && !before.accepting_applications && req.body.accepting_applications) {
    sets.push('closed_at = NULL');
  }

  params.push(id);
  await pool.query(`UPDATE programmes SET ${sets.join(', ')} WHERE id = $${n}`, params);
  const after = await getProgrammeRow(id);

  const acceptingChanged = before.accepting_applications !== after.accepting_applications;
  await logAction({
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

app.get('/api/admin/dashboard', requireOfficer, requireAdmin, async (req, res) => {
  const { rows: totalRows } = await pool.query(`
    SELECT
      COUNT(*) AS total_applications,
      SUM(CASE WHEN current_status NOT IN ('completed','rejected') THEN 1 ELSE 0 END) AS open_count,
      SUM(CASE WHEN current_status = 'completed' THEN 1 ELSE 0 END) AS completed_count,
      SUM(CASE WHEN current_status = 'rejected' THEN 1 ELSE 0 END) AS rejected_count,
      SUM(CASE WHEN flagged_after_close = 1 THEN 1 ELSE 0 END) AS flagged_count
    FROM applications
  `);
  const totals = totalRows[0];

  const { rows: byStatus } = await pool.query(`
    SELECT current_status AS status, COUNT(*) AS n
    FROM applications GROUP BY current_status
  `);

  const { rows: completedRows } = await pool.query(`
    SELECT a.programme_id,
           p.code AS programme_code,
           p.name AS programme_name,
           EXTRACT(EPOCH FROM comp.created_at - rec.created_at) / 86400.0 AS days
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
  `);

  const overall = computeStats(completedRows.map(r => parseFloat(r.days)));

  const perProgrammeMap = {};
  for (const r of completedRows) {
    const k = r.programme_id;
    if (!perProgrammeMap[k]) perProgrammeMap[k] = { programme_id: k, programme_code: r.programme_code, programme_name: r.programme_name, durations: [] };
    perProgrammeMap[k].durations.push(parseFloat(r.days));
  }
  const perProgrammeStats = Object.values(perProgrammeMap).map(p => ({
    programme_id: p.programme_id,
    programme_code: p.programme_code,
    programme_name: p.programme_name,
    ...computeStats(p.durations)
  }));

  const { rows: allProgrammes } = await pool.query('SELECT id, code, name FROM programmes');
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

  const { rows: officerLoad } = await pool.query(`
    SELECT o.id AS officer_id, o.name AS officer_name,
           SUM(CASE WHEN a.current_status NOT IN ('completed','rejected') THEN 1 ELSE 0 END) AS open_count,
           COUNT(a.id) AS total_count
    FROM officers o
    LEFT JOIN applications a ON a.assigned_officer_id = o.id
    WHERE o.is_active = 1
    GROUP BY o.id, o.name
    ORDER BY open_count DESC, o.name
  `);

  res.json({
    totals,
    by_status: byStatus,
    time_to_completion: { overall, per_programme: perProgrammeStats },
    officer_caseload: officerLoad,
    generated_at: new Date().toISOString()
  });
});

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

app.get('/api/admin/audit-log', requireOfficer, requireAdmin, async (req, res) => {
  const { limit, before, action, target_kind, target_id } = req.query;
  const rows = await listAuditLog({
    limit: limit ? Number(limit) : 50,
    before: before ? Number(before) : null,
    action: action || null,
    target_kind: target_kind || null,
    target_id: target_id ? Number(target_id) : null
  });
  res.json({ entries: rows });
});

} // end SERVE_ADMIN

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

let _initDone = false;
async function ensureInit() {
  if (_initDone) return;
  await initDb();
  _initDone = true;
}

app.use(async (req, res, next) => {
  try { await ensureInit(); next(); }
  catch (e) { res.status(503).json({ error: 'Database not ready' }); }
});

if (require.main === module) {
  ensureInit().then(() => {
    app.listen(PORT, () => {
      console.log(`\nGovBB Application Tracker pilot (mode: ${APP_MODE})`);
      if (SERVE_PUBLIC) console.log(`  http://localhost:${PORT}/                  citizen tracker`);
      if (SERVE_ADMIN) {
        console.log(`  http://localhost:${PORT}/submit-test       demo form submission`);
        console.log(`  http://localhost:${PORT}/officer/login     officer console`);
      }
      console.log(`  Database:           PostgreSQL (${process.env.DATABASE_URL ? 'configured' : 'localhost'})`);
    });
  }).catch(e => {
    if (e.code === 'ECONNREFUSED') {
      console.error('FATAL: Cannot connect to PostgreSQL. Set DATABASE_URL in your environment.');
    } else {
      console.error('FATAL: failed to start:', e);
    }
    process.exit(1);
  });
}

module.exports = app;
