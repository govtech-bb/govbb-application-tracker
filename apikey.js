const crypto = require('crypto');
const { pool } = require('./db');

const SCRYPT_KEYLEN = 32;
const SCRYPT_SALT = process.env.API_KEY_SALT || 'govbb-tracker-api-key-salt';
const SCRYPT_OPTS = { N: 16384, r: 8, p: 1 };

function hashKey(rawKey) {
  return crypto.scryptSync(rawKey, SCRYPT_SALT, SCRYPT_KEYLEN, SCRYPT_OPTS).toString('hex');
}

function extractKey(req) {
  const headerKey = req.header('X-API-Key');
  if (headerKey) return headerKey.trim();
  const auth = req.header('Authorization');
  if (auth && /^Bearer\s+/i.test(auth)) return auth.replace(/^Bearer\s+/i, '').trim();
  return null;
}

async function requireApiKey(req, res, next) {
  const raw = extractKey(req);
  if (!raw) {
    return res.status(401).json({ error: 'API key required. Send X-API-Key header or Authorization: Bearer <key>.' });
  }
  const { rows } = await pool.query(`
    SELECT id, name, scope FROM api_clients WHERE key_hash = $1
  `, [hashKey(raw)]);
  const client = rows[0];
  if (!client) {
    return res.status(401).json({ error: 'Invalid API key.' });
  }
  await pool.query(`UPDATE api_clients SET last_used_at = NOW() WHERE id = $1`, [client.id]);
  req.apiClient = client;
  next();
}

async function issueKey(name, scope = null, plaintext = null) {
  const raw = plaintext || ('sk_' + crypto.randomBytes(24).toString('base64url'));
  const hash = hashKey(raw);
  const { rows } = await pool.query(`
    INSERT INTO api_clients (name, key_hash, scope) VALUES ($1, $2, $3)
    ON CONFLICT(key_hash) DO UPDATE SET name = EXCLUDED.name, scope = EXCLUDED.scope
    RETURNING id
  `, [name, hash, scope]);
  return { id: rows[0].id, name, plaintext: raw };
}

module.exports = { requireApiKey, issueKey, hashKey };
