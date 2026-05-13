const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { pool, withTransaction } = require('./db');

const TOKEN_TTL_HOURS = Number(process.env.PASSWORD_TOKEN_TTL_HOURS) || 24;

function hashToken(plaintext) {
  return crypto.createHash('sha256').update(String(plaintext)).digest('hex');
}

async function issueToken({ officerId, purpose = 'reset', issuedByOfficerId = null }) {
  const plaintext = crypto.randomBytes(32).toString('base64url');
  const tokenHash = hashToken(plaintext);
  const expiresAt = new Date(Date.now() + TOKEN_TTL_HOURS * 3600 * 1000)
    .toISOString().replace('T', ' ').slice(0, 19);

  await pool.query(`
    INSERT INTO password_reset_tokens (officer_id, token_hash, purpose, expires_at, created_by_officer_id)
    VALUES ($1, $2, $3, $4, $5)
  `, [officerId, tokenHash, purpose, expiresAt, issuedByOfficerId]);

  return { plaintext, expires_at: expiresAt };
}

async function findValidToken(plaintext) {
  if (!plaintext || typeof plaintext !== 'string') return null;
  const tokenHash = hashToken(plaintext);
  const { rows } = await pool.query(`
    SELECT t.id, t.officer_id, t.purpose, t.expires_at, t.used_at,
           o.id AS officer_id_2, o.username, o.name, o.email, o.is_active
    FROM password_reset_tokens t
    JOIN officers o ON o.id = t.officer_id
    WHERE t.token_hash = $1
  `, [tokenHash]);
  const row = rows[0];
  if (!row) return { error: 'unknown' };
  if (row.used_at) return { error: 'used' };
  if (new Date(row.expires_at + 'Z') < new Date()) return { error: 'expired' };
  if (!row.is_active) return { error: 'inactive_officer' };
  return {
    id: row.id,
    officer_id: row.officer_id,
    purpose: row.purpose,
    expires_at: row.expires_at,
    officer: { id: row.officer_id, username: row.username, name: row.name, email: row.email }
  };
}

async function consumeTokenAndSetPassword(tokenId, officerId, passwordHash) {
  return withTransaction(async (client) => {
    await client.query(`UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1`, [tokenId]);
    await client.query(`
      UPDATE password_reset_tokens
      SET used_at = COALESCE(used_at, NOW())
      WHERE officer_id = $1 AND used_at IS NULL
    `, [officerId]);
    await client.query(`UPDATE officers SET password_hash = $1, is_active = 1 WHERE id = $2`, [passwordHash, officerId]);
  });
}

const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', 'passw0rd',
  '123456789012', '123456789', 'qwertyuiopas', 'qwerty123456',
  'letmein12345', 'welcome12345', 'admin1234567', 'changeme1234',
  'iloveyou1234', 'monkey123456', 'abcdefghijkl', '111111111111',
  '000000000000', 'qwertyqwerty', 'passwordpass', 'p@ssword1234'
]);

const WEAK_PATTERNS = [
  { re: /^p[a4@]ssw[o0]rd[\W_\d]*$/i, why: "Variants of \"password\" are still on every breach list." },
  { re: /^\d+$/, why: 'A digits-only password is far easier to crack than a passphrase.' },
  { re: /^(.)\1+$/, why: "A single repeated character isn't a password." },
  { re: /^(qwerty|asdfgh|zxcvbn|abcdef|letmein|welcome|admin|iloveyou|monkey|dragon|master|hello|football|sunshine)[\W_\d]*$/i, why: 'That base word is on every common-password list.' },
  { re: /^(.{4,8})\1+$/i, why: 'Repeating a short word twice is a known weak pattern.' }
];

const MIN_LENGTH = 12;

function validatePassword(pw, { email = '' } = {}) {
  const errors = [];
  const warnings = [];
  pw = String(pw || '');

  if (pw.length < MIN_LENGTH) errors.push(`Use at least ${MIN_LENGTH} characters.`);
  if (pw.length > 200) errors.push('Maximum 200 characters.');
  if (COMMON_PASSWORDS.has(pw.toLowerCase())) errors.push("That's on the most-common-passwords list. Pick something less guessable.");
  for (const wp of WEAK_PATTERNS) {
    if (wp.re.test(pw)) { errors.push(wp.why); break; }
  }
  if (email && pw.toLowerCase().includes(email.split('@')[0].toLowerCase()) && pw.length < 20) {
    errors.push("Don't include your email address in the password.");
  }

  const hasLower = /[a-z]/.test(pw);
  const hasUpper = /[A-Z]/.test(pw);
  const hasDigit = /\d/.test(pw);
  const hasSymbol = /[^A-Za-z0-9]/.test(pw);
  const variety = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;

  if (variety < 2) warnings.push('Mix at least two of: lowercase, uppercase, digits, symbols.');
  if (/^(.)\1+$/.test(pw)) warnings.push("Don't use a single repeating character.");
  if (/^(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf)/i.test(pw)) warnings.push('Avoid keyboard or number runs at the start.');

  let strength = 0;
  if (pw.length >= 12) strength = 1;
  if (pw.length >= 14) strength = 2;
  if (pw.length >= 16) strength = 3;
  if (pw.length >= 20) strength = 4;
  if (variety >= 3) strength = Math.min(5, strength + 1);
  if (errors.length) strength = 0;

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    strength,
    strength_label: ['Too short','Weak','OK','Good','Strong','Excellent'][strength]
  };
}

const RULES = {
  min_length: MIN_LENGTH,
  max_length: 200,
  must: [
    `At least ${MIN_LENGTH} characters`,
    'Not on the most-common-passwords list'
  ],
  recommended: [
    'Mix of upper case, lower case, digits and symbols',
    'Easier-to-remember passphrases like "correct horse battery staple" beat clever substitutions'
  ]
};

module.exports = {
  issueToken,
  findValidToken,
  consumeTokenAndSetPassword,
  validatePassword,
  hashPassword: (pw) => bcrypt.hashSync(pw, 10),
  RULES,
  TOKEN_TTL_HOURS
};
