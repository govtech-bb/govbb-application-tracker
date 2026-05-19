const pg = require('pg');

pg.types.setTypeParser(1114, str => str);
pg.types.setTypeParser(1184, str => str);

function sslConfig() {
  if (process.env.DATABASE_SSL === 'false') return false;
  const url = process.env.DATABASE_URL || '';
  if (!url || url.includes('localhost') || url.includes('127.0.0.1')) return false;
  if (process.env.DATABASE_CA_CERT) {
    return { ca: process.env.DATABASE_CA_CERT, rejectUnauthorized: true };
  }
  return { rejectUnauthorized: true };
}

const IS_SERVERLESS = Boolean(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/govbb_tracker',
  ssl: sslConfig(),
  // Serverless: keep pool small, recycle connections before Neon kills them
  max: IS_SERVERLESS ? 3 : 10,
  idleTimeoutMillis: IS_SERVERLESS ? 10_000 : 30_000,
  connectionTimeoutMillis: 5_000
});

// Log and discard broken connections instead of crashing the process
pool.on('error', (err) => {
  console.error('[pg] idle client error:', err.message);
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS programmes (
      id SERIAL PRIMARY KEY,
      code TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      ministry TEXT NOT NULL,
      default_sla_days INTEGER NOT NULL DEFAULT 14,
      allowed_statuses TEXT NOT NULL,
      contact_email TEXT,
      contact_phone TEXT,
      accepting_applications INTEGER NOT NULL DEFAULT 1,
      closed_at TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS applicants (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      phone TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS officers (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      ministry TEXT NOT NULL,
      role TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS applications (
      id SERIAL PRIMARY KEY,
      code TEXT NOT NULL UNIQUE,
      programme_id INTEGER NOT NULL REFERENCES programmes(id),
      applicant_id INTEGER NOT NULL REFERENCES applicants(id),
      current_status TEXT NOT NULL,
      current_status_at TIMESTAMP NOT NULL,
      assigned_officer_id INTEGER REFERENCES officers(id),
      form_data TEXT,
      flagged_after_close INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS status_events (
      id SERIAL PRIMARY KEY,
      application_id INTEGER NOT NULL REFERENCES applications(id),
      status TEXT NOT NULL,
      citizen_message TEXT,
      internal_note TEXT,
      by_officer_id INTEGER REFERENCES officers(id),
      action_type TEXT,
      action_label TEXT,
      action_response TEXT,
      action_response_at TIMESTAMP,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS uploads (
      id SERIAL PRIMARY KEY,
      status_event_id INTEGER NOT NULL REFERENCES status_events(id),
      application_id INTEGER NOT NULL REFERENCES applications(id),
      original_filename TEXT NOT NULL,
      stored_filename TEXT NOT NULL,
      mime_type TEXT,
      size_bytes INTEGER,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      application_id INTEGER NOT NULL REFERENCES applications(id),
      kind TEXT NOT NULL,
      channel TEXT NOT NULL DEFAULT 'email',
      recipient TEXT NOT NULL,
      subject TEXT,
      body_path TEXT,
      sent_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS api_clients (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      key_hash TEXT NOT NULL UNIQUE,
      scope TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      last_used_at TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS officer_programmes (
      officer_id INTEGER NOT NULL REFERENCES officers(id) ON DELETE CASCADE,
      programme_id INTEGER NOT NULL REFERENCES programmes(id) ON DELETE CASCADE,
      granted_at TIMESTAMP NOT NULL DEFAULT NOW(),
      granted_by_officer_id INTEGER REFERENCES officers(id),
      PRIMARY KEY (officer_id, programme_id)
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id SERIAL PRIMARY KEY,
      actor_officer_id INTEGER REFERENCES officers(id),
      actor_label TEXT,
      action TEXT NOT NULL,
      target_kind TEXT,
      target_id INTEGER,
      before_json TEXT,
      after_json TEXT,
      metadata_json TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id SERIAL PRIMARY KEY,
      officer_id INTEGER NOT NULL REFERENCES officers(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      purpose TEXT NOT NULL DEFAULT 'reset',
      expires_at TIMESTAMP NOT NULL,
      used_at TIMESTAMP,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      created_by_officer_id INTEGER REFERENCES officers(id)
    );

    CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(current_status);
    CREATE INDEX IF NOT EXISTS idx_applications_programme ON applications(programme_id);
    CREATE INDEX IF NOT EXISTS idx_status_events_app ON status_events(application_id);
    CREATE INDEX IF NOT EXISTS idx_notifications_app ON notifications(application_id);
    CREATE INDEX IF NOT EXISTS idx_api_clients_keyhash ON api_clients(key_hash);
    CREATE INDEX IF NOT EXISTS idx_officer_programmes_officer ON officer_programmes(officer_id);
    CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target_kind, target_id);
    CREATE INDEX IF NOT EXISTS idx_pwreset_token_hash ON password_reset_tokens(token_hash);
    CREATE INDEX IF NOT EXISTS idx_pwreset_officer ON password_reset_tokens(officer_id);
    CREATE INDEX IF NOT EXISTS idx_uploads_status_event ON uploads(status_event_id);
    CREATE INDEX IF NOT EXISTS idx_uploads_application ON uploads(application_id);
  `);

  try {
    const r = await pool.query(`UPDATE officers SET username = email WHERE username != email`);
    if (r.rowCount > 0) console.log(`[migrate] aligned ${r.rowCount} officer username(s) to email`);
  } catch (e) {
    console.error('[migrate] WARNING: could not sync username→email:', e.message);
  }

  try {
    await pool.query(`ALTER TABLE applications ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP`);
  } catch (e) {
    console.error('[migrate] WARNING: could not add deleted_at column:', e.message);
  }
}

async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

async function insertStatusEvent(event) {
  return withTransaction(async (client) => {
    const { rows } = await client.query(`
      INSERT INTO status_events (
        application_id, status, citizen_message, internal_note, by_officer_id,
        action_type, action_label
      ) VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *
    `, [
      event.application_id,
      event.status,
      event.citizen_message || null,
      event.internal_note || null,
      event.by_officer_id || null,
      event.action_type || null,
      event.action_label || null
    ]);
    await client.query(`
      UPDATE applications SET current_status = $1, current_status_at = NOW() WHERE id = $2
    `, [event.status, event.application_id]);
    return rows[0];
  });
}

async function getApplicationByCode(code) {
  const { rows } = await pool.query(`
    SELECT a.*, p.code AS programme_code, p.name AS programme_name, p.ministry,
           p.contact_email, p.contact_phone, p.default_sla_days,
           ap.name AS applicant_name, ap.email AS applicant_email, ap.phone AS applicant_phone,
           o.name AS assigned_officer_name, o.email AS assigned_officer_email
    FROM applications a
    JOIN programmes p ON p.id = a.programme_id
    JOIN applicants ap ON ap.id = a.applicant_id
    LEFT JOIN officers o ON o.id = a.assigned_officer_id
    WHERE a.code = $1 AND a.deleted_at IS NULL
  `, [code]);
  const app = rows[0];
  if (!app) return null;
  const evResult = await pool.query(`
    SELECT se.id, se.status, se.citizen_message, se.internal_note, se.created_at,
           se.action_type, se.action_label, se.action_response, se.action_response_at,
           o.name AS by_officer_name
    FROM status_events se
    LEFT JOIN officers o ON o.id = se.by_officer_id
    WHERE se.application_id = $1
    ORDER BY se.created_at ASC, se.id ASC
  `, [app.id]);
  app.timeline = evResult.rows;
  await attachUploads(app.timeline);
  return app;
}

async function attachUploads(timeline) {
  if (!timeline || timeline.length === 0) return;
  const ids = timeline.map(t => t.id);
  const { rows } = await pool.query(`
    SELECT id, status_event_id, original_filename, mime_type, size_bytes, created_at
    FROM uploads
    WHERE status_event_id = ANY($1::int[])
    ORDER BY id ASC
  `, [ids]);
  const byEvent = {};
  for (const r of rows) {
    if (!byEvent[r.status_event_id]) byEvent[r.status_event_id] = [];
    byEvent[r.status_event_id].push(r);
  }
  for (const t of timeline) {
    t.uploads = byEvent[t.id] || [];
  }
}

async function getPendingAction(applicationId) {
  const { rows } = await pool.query(`
    SELECT id, status, action_type, action_label, created_at
    FROM status_events
    WHERE application_id = $1
      AND action_type IS NOT NULL
      AND action_response IS NULL
      AND action_response_at IS NULL
      AND status = 'action_needed'
    ORDER BY created_at DESC, id DESC
    LIMIT 1
  `, [applicationId]);
  return rows[0] || null;
}

async function recordActionResponse({ event_id, application_id, response_text, file }) {
  return withTransaction(async (client) => {
    await client.query(`
      UPDATE status_events
      SET action_response = $1, action_response_at = NOW()
      WHERE id = $2
    `, [response_text || null, event_id]);
    let uploadId = null;
    if (file) {
      const { rows } = await client.query(`
        INSERT INTO uploads (status_event_id, application_id, original_filename, stored_filename, mime_type, size_bytes)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
      `, [event_id, application_id, file.original_filename, file.stored_filename, file.mime_type || null, file.size_bytes || null]);
      uploadId = rows[0].id;
    }
    return uploadId;
  });
}

async function listApplicationsForOfficer(officerId, isAdmin) {
  if (isAdmin || officerId == null) {
    const { rows } = await pool.query(`
      SELECT a.id, a.code, a.current_status, a.current_status_at, a.created_at,
             a.flagged_after_close,
             p.code AS programme_code, p.name AS programme_name, p.ministry,
             p.accepting_applications,
             ap.name AS applicant_name, ap.email AS applicant_email,
             o.id AS assigned_officer_id, o.name AS assigned_officer_name
      FROM applications a
      JOIN programmes p ON p.id = a.programme_id
      JOIN applicants ap ON ap.id = a.applicant_id
      LEFT JOIN officers o ON o.id = a.assigned_officer_id
      WHERE a.deleted_at IS NULL
      ORDER BY a.current_status_at DESC
    `);
    return rows;
  }
  const { rows } = await pool.query(`
    SELECT a.id, a.code, a.current_status, a.current_status_at, a.created_at,
           a.flagged_after_close,
           p.code AS programme_code, p.name AS programme_name, p.ministry,
           p.accepting_applications,
           ap.name AS applicant_name, ap.email AS applicant_email,
           o.id AS assigned_officer_id, o.name AS assigned_officer_name
    FROM applications a
    JOIN programmes p ON p.id = a.programme_id
    JOIN applicants ap ON ap.id = a.applicant_id
    LEFT JOIN officers o ON o.id = a.assigned_officer_id
    WHERE a.deleted_at IS NULL AND EXISTS (
      SELECT 1 FROM officer_programmes op
      WHERE op.officer_id = $1 AND op.programme_id = a.programme_id
    )
    ORDER BY a.current_status_at DESC
  `, [officerId]);
  return rows;
}

async function listDeletedApplications() {
  const { rows } = await pool.query(`
    SELECT a.id, a.code, a.current_status, a.current_status_at, a.created_at,
           a.deleted_at, a.flagged_after_close,
           p.code AS programme_code, p.name AS programme_name,
           ap.name AS applicant_name, ap.email AS applicant_email,
           o.name AS assigned_officer_name
    FROM applications a
    JOIN programmes p ON p.id = a.programme_id
    JOIN applicants ap ON ap.id = a.applicant_id
    LEFT JOIN officers o ON o.id = a.assigned_officer_id
    WHERE a.deleted_at IS NOT NULL
    ORDER BY a.deleted_at DESC
  `);
  return rows;
}

async function listProgrammesForOfficer(officerId) {
  const { rows } = await pool.query(`
    SELECT p.id, p.code, p.name
    FROM programmes p
    JOIN officer_programmes op ON op.programme_id = p.id
    WHERE op.officer_id = $1
    ORDER BY p.name
  `, [officerId]);
  return rows;
}

async function officerCanAccessApplication(officerId, isAdmin, applicationId) {
  if (isAdmin) return true;
  const { rows } = await pool.query(`
    SELECT 1
    FROM applications a
    JOIN officer_programmes op
      ON op.programme_id = a.programme_id AND op.officer_id = $1
    WHERE a.id = $2
  `, [officerId, applicationId]);
  return rows.length > 0;
}

async function getApplicationById(id) {
  const { rows } = await pool.query(`
    SELECT a.*, p.code AS programme_code, p.name AS programme_name, p.ministry,
           p.contact_email, p.contact_phone,
           ap.name AS applicant_name, ap.email AS applicant_email, ap.phone AS applicant_phone,
           o.name AS assigned_officer_name
    FROM applications a
    JOIN programmes p ON p.id = a.programme_id
    JOIN applicants ap ON ap.id = a.applicant_id
    LEFT JOIN officers o ON o.id = a.assigned_officer_id
    WHERE a.id = $1
  `, [id]);
  const app = rows[0];
  if (!app) return null;
  try { app.form_data = app.form_data ? JSON.parse(app.form_data) : null; }
  catch (_) { app.form_data = null; }
  const evResult = await pool.query(`
    SELECT se.id, se.status, se.citizen_message, se.internal_note, se.created_at,
           se.action_type, se.action_label, se.action_response, se.action_response_at,
           o.name AS by_officer_name
    FROM status_events se
    LEFT JOIN officers o ON o.id = se.by_officer_id
    WHERE se.application_id = $1
    ORDER BY se.created_at ASC, se.id ASC
  `, [app.id]);
  app.timeline = evResult.rows;
  await attachUploads(app.timeline);
  return app;
}

module.exports = {
  pool,
  initDb,
  withTransaction,
  insertStatusEvent,
  getApplicationByCode,
  getApplicationById,
  listApplicationsForOfficer,
  listDeletedApplications,
  listProgrammesForOfficer,
  officerCanAccessApplication,
  getPendingAction,
  recordActionResponse
};
