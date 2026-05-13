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
  const where = [];
  const params = [];
  let n = 1;
  if (before != null) { where.push(`id < $${n++}`); params.push(Number(before)); }
  if (action) { where.push(`action = $${n++}`); params.push(action); }
  if (target_kind) { where.push(`target_kind = $${n++}`); params.push(target_kind); }
  if (target_id != null) { where.push(`target_id = $${n++}`); params.push(Number(target_id)); }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
  params.push(Math.max(1, Math.min(500, Number(limit) || 50)));
  const { rows } = await pool.query(`
    SELECT id, actor_officer_id, actor_label, action,
           target_kind, target_id,
           before_json, after_json, metadata_json,
           created_at
    FROM audit_log
    ${whereSql}
    ORDER BY id DESC
    LIMIT $${n}
  `, params);
  return rows.map(r => ({
    ...r,
    before: r.before_json ? safeParse(r.before_json) : null,
    after:  r.after_json  ? safeParse(r.after_json)  : null,
    metadata: r.metadata_json ? safeParse(r.metadata_json) : null
  }));
}

module.exports = { logAction, actorFromReq, requestMeta, listAuditLog };
