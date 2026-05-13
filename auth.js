const bcrypt = require('bcryptjs');
const { pool } = require('./db');

async function authenticateOfficer(username, password) {
  const { rows } = await pool.query(`
    SELECT id, username, password_hash, name, email, ministry, role,
           is_admin, is_active
    FROM officers
    WHERE username = $1
  `, [username]);
  const officer = rows[0];
  if (!officer) return null;
  if (!officer.is_active) return { _inactive: true };
  const ok = await bcrypt.compare(password, officer.password_hash);
  if (!ok) return null;
  delete officer.password_hash;
  officer.is_admin = Boolean(officer.is_admin);
  officer.is_active = Boolean(officer.is_active);
  return officer;
}

function requireOfficer(req, res, next) {
  if (req.session && req.session.officer) return next();
  if (req.accepts('html') && !req.path.startsWith('/api/')) {
    return res.redirect('/officer/login?next=' + encodeURIComponent(req.originalUrl));
  }
  return res.status(401).json({ error: 'Not authenticated' });
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.officer) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  if (!req.session.officer.is_admin) {
    return res.status(403).json({ error: 'Admin role required' });
  }
  return next();
}

module.exports = { authenticateOfficer, requireOfficer, requireAdmin };
