/**
 * SQLite schema + helpers for the GovBB application tracker pilot.
 *
 * Tables follow the data model in pilot-brief.md:
 *   programmes         master list of services that can be tracked
 *   applicants         person who applied (PII source of truth)
 *   applications       one row per submission, with cached current status
 *   officers           back-office users (synced from SSO in production)
 *   status_events      append-only audit log of every status change
 *   notifications      audit log of every email we sent
 *
 * Design choices for the pilot:
 *   - SQLite (better-sqlite3) — zero install, single file at data/tracker.db.
 *     Production should swap for Postgres; the schema is portable.
 *   - status_events is the source of truth. applications.current_status is
 *     a denormalised cache for fast list/filter, kept in sync inside a
 *     transaction whenever a new event is inserted.
 *   - allowed_statuses on programmes is a JSON array so different programmes
 *     can have different state machines without schema changes.
 */

const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.TRACKER_DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_PATH = path.join(DATA_DIR, 'tracker.db');
const db = new Database(DB_PATH);
// WAL is the recommended mode for production. Some filesystems (e.g. fuse
// mounts and certain network shares) don't support it; fall back silently
// so the pilot keeps working on developer machines and CI.
try { db.pragma('journal_mode = WAL'); }
catch (e) { /* fall back to default rollback journal */ }
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS programmes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  ministry TEXT NOT NULL,
  default_sla_days INTEGER NOT NULL DEFAULT 14,
  allowed_statuses TEXT NOT NULL,
  contact_email TEXT,
  contact_phone TEXT,
  accepting_applications INTEGER NOT NULL DEFAULT 1,
  closed_at TEXT
);

CREATE TABLE IF NOT EXISTS applicants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS officers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  ministry TEXT NOT NULL,
  role TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS applications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  programme_id INTEGER NOT NULL REFERENCES programmes(id),
  applicant_id INTEGER NOT NULL REFERENCES applicants(id),
  current_status TEXT NOT NULL,
  current_status_at TEXT NOT NULL,
  assigned_officer_id INTEGER REFERENCES officers(id),
  form_data TEXT,
  flagged_after_close INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS status_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  application_id INTEGER NOT NULL REFERENCES applications(id),
  status TEXT NOT NULL,
  citizen_message TEXT,
  internal_note TEXT,
  by_officer_id INTEGER REFERENCES officers(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  application_id INTEGER NOT NULL REFERENCES applications(id),
  kind TEXT NOT NULL,
  channel TEXT NOT NULL DEFAULT 'email',
  recipient TEXT NOT NULL,
  subject TEXT,
  body_path TEXT,
  sent_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS api_clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  scope TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT
);

-- Many-to-many: which officers can see/manage which programmes.
-- An officer with ZERO rows in this table sees nothing. The seed and the
-- "create officer" admin path both populate every programme by default; the
-- admin can then revoke specific rows.
CREATE TABLE IF NOT EXISTS officer_programmes (
  officer_id INTEGER NOT NULL REFERENCES officers(id) ON DELETE CASCADE,
  programme_id INTEGER NOT NULL REFERENCES programmes(id) ON DELETE CASCADE,
  granted_at TEXT NOT NULL DEFAULT (datetime('now')),
  granted_by_officer_id INTEGER REFERENCES officers(id),
  PRIMARY KEY (officer_id, programme_id)
);

-- Append-only audit log of every meaningful action in the system. The
-- before/after JSON columns capture the diff so you can reconstruct any
-- entity's history without complex joins.
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_officer_id INTEGER REFERENCES officers(id),
  actor_label TEXT,           -- denormalised for cases where the officer is later deleted
  action TEXT NOT NULL,       -- e.g. 'officer.create', 'application.status_change', 'login.fail'
  target_kind TEXT,           -- 'officer' | 'programme' | 'application' | 'session' | 'api_client' | null
  target_id INTEGER,
  before_json TEXT,
  after_json TEXT,
  metadata_json TEXT,         -- free-form: ip, user agent, application code, etc.
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Password setup / reset tokens. The plaintext token is sent in the email
-- link; only the SHA-256 hash is stored. Tokens are single-use and expire
-- (default 24h, configurable via PASSWORD_TOKEN_TTL_HOURS).
CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  officer_id INTEGER NOT NULL REFERENCES officers(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  purpose TEXT NOT NULL DEFAULT 'reset',  -- 'set_initial' | 'reset'
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
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
`);

/* =========================================================
   Idempotent migrations for databases created before these columns existed.
   Safe to run on every boot — each ALTER is wrapped in a column-presence check.
   ========================================================= */
function tableHasColumn(table, column) {
  return db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === column);
}
function addColumnIfMissing(table, column, definition) {
  if (!tableHasColumn(table, column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}
addColumnIfMissing('officers',     'is_admin',                 'INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('officers',     'is_active',                'INTEGER NOT NULL DEFAULT 1');
addColumnIfMissing('programmes',   'accepting_applications',   'INTEGER NOT NULL DEFAULT 1');
addColumnIfMissing('programmes',   'closed_at',                'TEXT');
addColumnIfMissing('applications', 'flagged_after_close',      'INTEGER NOT NULL DEFAULT 0');

// Email-as-username: officers now log in with their email address, not a
// short username. To avoid breaking pre-migration deployments, sync the
// username column to the email column for any rows where they differ.
// Idempotent — runs every boot but only changes rows that need it.
try {
  const r = db.prepare(`UPDATE officers SET username = email WHERE username != email`).run();
  if (r.changes > 0) console.log(`[migrate] aligned ${r.changes} officer username(s) to email`);
} catch (e) {
  // If two officers happened to share an email, this would fail. Surface it
  // loudly rather than crashing the boot — they can be deduped manually.
  console.error('[migrate] WARNING: could not sync username→email:', e.message);
}

/* =========================================================
   Helpers
   ========================================================= */

/**
 * Insert a status event AND update the cached current_status on the
 * application, atomically. Returns the inserted event row.
 */
const insertStatusEvent = db.transaction((event) => {
  const stmt = db.prepare(`
    INSERT INTO status_events (application_id, status, citizen_message, internal_note, by_officer_id)
    VALUES (@application_id, @status, @citizen_message, @internal_note, @by_officer_id)
  `);
  const info = stmt.run({
    application_id: event.application_id,
    status: event.status,
    citizen_message: event.citizen_message || null,
    internal_note: event.internal_note || null,
    by_officer_id: event.by_officer_id || null
  });
  db.prepare(`
    UPDATE applications
    SET current_status = ?, current_status_at = datetime('now')
    WHERE id = ?
  `).run(event.status, event.application_id);
  return db.prepare('SELECT * FROM status_events WHERE id = ?').get(info.lastInsertRowid);
});

/** Fetch one application by reference code, joined with programme + applicant + timeline. */
function getApplicationByCode(code) {
  const app = db.prepare(`
    SELECT a.*, p.code AS programme_code, p.name AS programme_name, p.ministry,
           p.contact_email, p.contact_phone, p.default_sla_days,
           ap.name AS applicant_name, ap.email AS applicant_email, ap.phone AS applicant_phone,
           o.name AS assigned_officer_name, o.email AS assigned_officer_email
    FROM applications a
    JOIN programmes p ON p.id = a.programme_id
    JOIN applicants ap ON ap.id = a.applicant_id
    LEFT JOIN officers o ON o.id = a.assigned_officer_id
    WHERE a.code = ?
  `).get(code);
  if (!app) return null;
  app.timeline = db.prepare(`
    SELECT se.id, se.status, se.citizen_message, se.internal_note, se.created_at,
           o.name AS by_officer_name
    FROM status_events se
    LEFT JOIN officers o ON o.id = se.by_officer_id
    WHERE se.application_id = ?
    ORDER BY se.created_at ASC, se.id ASC
  `).all(app.id);
  return app;
}

/**
 * List for the officer console. If `officerId` is supplied AND the officer
 * is NOT an admin, the result is filtered to programmes they're assigned to.
 * Admins see everything.
 */
function listApplicationsForOfficer(officerId, isAdmin) {
  if (isAdmin || officerId == null) {
    return db.prepare(`
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
      ORDER BY a.current_status_at DESC
    `).all();
  }
  return db.prepare(`
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
    WHERE EXISTS (
      SELECT 1 FROM officer_programmes op
      WHERE op.officer_id = ? AND op.programme_id = a.programme_id
    )
    ORDER BY a.current_status_at DESC
  `).all(officerId);
}

/** Programmes assigned to a given officer. */
function listProgrammesForOfficer(officerId) {
  return db.prepare(`
    SELECT p.id, p.code, p.name
    FROM programmes p
    JOIN officer_programmes op ON op.programme_id = p.id
    WHERE op.officer_id = ?
    ORDER BY p.name
  `).all(officerId);
}

/** True when the officer is allowed to see/manage the given application. */
function officerCanAccessApplication(officerId, isAdmin, applicationId) {
  if (isAdmin) return true;
  const row = db.prepare(`
    SELECT 1
    FROM applications a
    JOIN officer_programmes op
      ON op.programme_id = a.programme_id AND op.officer_id = ?
    WHERE a.id = ?
  `).get(officerId, applicationId);
  return Boolean(row);
}

function getApplicationById(id) {
  const app = db.prepare(`
    SELECT a.*, p.code AS programme_code, p.name AS programme_name, p.ministry,
           p.contact_email, p.contact_phone,
           ap.name AS applicant_name, ap.email AS applicant_email, ap.phone AS applicant_phone,
           o.name AS assigned_officer_name
    FROM applications a
    JOIN programmes p ON p.id = a.programme_id
    JOIN applicants ap ON ap.id = a.applicant_id
    LEFT JOIN officers o ON o.id = a.assigned_officer_id
    WHERE a.id = ?
  `).get(id);
  if (!app) return null;
  // Parse the JSON-encoded form_data so the officer view can render it
  // without any JSON.parse on the client. Returned as null if missing or
  // unparseable; never throws.
  try { app.form_data = app.form_data ? JSON.parse(app.form_data) : null; }
  catch (_) { app.form_data = null; }
  app.timeline = db.prepare(`
    SELECT se.id, se.status, se.citizen_message, se.internal_note, se.created_at,
           o.name AS by_officer_name
    FROM status_events se
    LEFT JOIN officers o ON o.id = se.by_officer_id
    WHERE se.application_id = ?
    ORDER BY se.created_at ASC, se.id ASC
  `).all(app.id);
  return app;
}

module.exports = {
  db,
  insertStatusEvent,
  getApplicationByCode,
  getApplicationById,
  listApplicationsForOfficer,
  listProgrammesForOfficer,
  officerCanAccessApplication
};
