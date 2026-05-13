const { pool } = require('./db');

function safeJson(v) {
  if (v == null) return null;
  try { return JSON.stringify(v); } catch (_) { return null; }
}

async function logAction({
  actor = null,
  action,
  target_kind = null,
  target_id = null,
  before = null,
  after = null,
  metadata = null
}) {
  try {
    const { rows } = await pool.query(`
      INSERT INTO audit_log (
        actor_officer_id, actor_label,
        action, target_kind, target_id,
        before_json, after_json, metadata_json
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING id
    `, [
      actor && actor.id ? actor.id : null,
      actor ? `${actor.username} (${actor.name})` : null,
      action,
      target_kind,
      target_id == null ? null : Number(target_id),
      safeJson(before),
      safeJson(after),
      safeJson(metadata)
    ]);
    return rows[0].id;
  } catch (e) {
    console.error('[audit] failed to write audit row:', e.message);
    return null;
  }
}

function actorFromReq(req) {
  return (req && req.session && req.session.officer) || null;
}

function requestMeta(req, extra = {}) {
  return {
    ip: req && (req.ip || (req.connection && req.connection.remoteAddress)) || null,
    user_agent: req && req.headers && req.headers['user-agent'] || null,
    ...extra
  };
}

function safeParse(s) { try { return JSON.parse(s); } catch (_) { return null; } }

async function listAuditLog({ limit = 50, before = null, action = null, target_kind = null, target_id = null } = {}) {
  const safeLimit = Math.max(1, Math.min(500, Number(limit) || 50));
  const { rows } = await pool.query(`
    SELECT id, actor_officer_id, actor_label, action,
           target_kind, target_id,
           before_json, after_json, metadata_json,
           created_at
    FROM audit_log
    WHERE ($1::int IS NULL OR id < $1)
      AND ($2::text IS NULL OR action = $2)
      AND ($3::text IS NULL OR target_kind = $3)
      AND ($4::int IS NULL OR target_id = $4)
    ORDER BY id DESC
    LIMIT $5
  `, [
    before != null ? Number(before) : null,
    action || null,
    target_kind || null,
    target_id != null ? Number(target_id) : null,
    safeLimit
  ]);
  return rows.map(r => ({
    ...r,
    before: r.before_json ? safeParse(r.before_json) : null,
    after:  r.after_json  ? safeParse(r.after_json)  : null,
    metadata: r.metadata_json ? safeParse(r.metadata_json) : null
  }));
}

module.exports = { logAction, actorFromReq, requestMeta, listAuditLog };
