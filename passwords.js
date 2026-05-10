/**
 * Password setup tokens + complexity rules.
 *
 * Tokens
 * ------
 *   - Generated as 32 bytes of crypto-strong random, base64url-encoded.
 *   - Only the SHA-256 hash is stored; the plaintext lives only in the email
 *     we send to the user.
 *   - Single-use: marked used_at on success. Replay returns "expired or used".
 *   - TTL: PASSWORD_TOKEN_TTL_HOURS env var, default 24.
 *
 * Complexity
 * ----------
 *   Required:
 *     - Length >= 12 characters.
 *     - Not in a small embedded list of common passwords.
 *   Recommended (warned, not blocked):
 *     - Mix of letter cases.
 *     - At least one digit.
 *     - At least one symbol.
 *
 *   The strength meter is a simple length+variety heuristic, not a real
 *   entropy estimate (zxcvbn is overkill for the pilot).
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { db } = require('./db');

const TOKEN_TTL_HOURS = Number(process.env.PASSWORD_TOKEN_TTL_HOURS) || 24;

/* =========================================================
   Tokens
   ========================================================= */

function hashToken(plaintext) {
  return crypto.createHash('sha256').update(String(plaintext)).digest('hex');
}

/**
 * Issue a password-setup token for an officer.
 * Returns { plaintext, expires_at } — the plaintext goes into the email link.
 */
function issueToken({ officerId, purpose = 'reset', issuedByOfficerId = null }) {
  const plaintext = crypto.randomBytes(32).toString('base64url');
  const tokenHash = hashToken(plaintext);

  const expiresAt = new Date(Date.now() + TOKEN_TTL_HOURS * 3600 * 1000)
    .toISOString().replace('T', ' ').slice(0, 19);

  db.prepare(`
    INSERT INTO password_reset_tokens (officer_id, token_hash, purpose, expires_at, created_by_officer_id)
    VALUES (?, ?, ?, ?, ?)
  `).run(officerId, tokenHash, purpose, expiresAt, issuedByOfficerId);

  return { plaintext, expires_at: expiresAt };
}

/**
 * Look up a token by its plaintext (which we hash to compare).
 * Returns the token row joined with officer info, or null.
 */
function findValidToken(plaintext) {
  if (!plaintext || typeof plaintext !== 'string') return null;
  const tokenHash = hashToken(plaintext);
  const row = db.prepare(`
    SELECT t.id, t.officer_id, t.purpose, t.expires_at, t.used_at,
           o.id AS officer_id_2, o.username, o.name, o.email, o.is_active
    FROM password_reset_tokens t
    JOIN officers o ON o.id = t.officer_id
    WHERE t.token_hash = ?
  `).get(tokenHash);
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

/**
 * Atomically: mark token used AND set the officer's password hash. Also
 * invalidates any other outstanding tokens for the same officer (so a
 * leaked older token can't be used after a successful set).
 */
const consumeTokenAndSetPassword = db.transaction((tokenId, officerId, passwordHash) => {
  db.prepare(`UPDATE password_reset_tokens SET used_at = datetime('now') WHERE id = ?`).run(tokenId);
  db.prepare(`
    UPDATE password_reset_tokens
    SET used_at = COALESCE(used_at, datetime('now'))
    WHERE officer_id = ? AND used_at IS NULL
  `).run(officerId);
  db.prepare(`UPDATE officers SET password_hash = ?, is_active = 1 WHERE id = ?`).run(passwordHash, officerId);
});

/* =========================================================
   Complexity
   ========================================================= */

// Embedded list of passwords we explicitly refuse. Far from complete but
// catches common embarrassments. For a real deployment, swap for a breach-list
// lookup (haveibeenpwned k-anonymity API).
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', 'passw0rd',
  '123456789012', '123456789', 'qwertyuiopas', 'qwerty123456',
  'letmein12345', 'welcome12345', 'admin1234567', 'changeme1234',
  'iloveyou1234', 'monkey123456', 'abcdefghijkl', '111111111111',
  '000000000000', 'qwertyqwerty', 'passwordpass', 'p@ssword1234'
]);

// Regex patterns that mark a password as "obviously weak" regardless of length.
const WEAK_PATTERNS = [
  // password / passw0rd / p@ssword / Password1234 / PASSWORDpassword etc.
  { re: /^p[a4@]ssw[o0]rd[\W_\d]*$/i, why: "Variants of \"password\" are still on every breach list." },
  // Pure digits, even long ones (e.g. 123456789012, 000000000000).
  { re: /^\d+$/, why: 'A digits-only password is far easier to crack than a passphrase.' },
  // Single character repeated.
  { re: /^(.)\1+$/, why: "A single repeated character isn't a password." },
  // Long keyboard run / common base ("qwerty…", "asdf…", "letmein", etc.) followed by anything.
  { re: /^(qwerty|asdfgh|zxcvbn|abcdef|letmein|welcome|admin|iloveyou|monkey|dragon|master|hello|football|sunshine)[\W_\d]*$/i, why: 'That base word is on every common-password list.' },
  // Two-stem patterns like "passwordpassword" or "qwertyqwerty".
  { re: /^(.{4,8})\1+$/i, why: 'Repeating a short word twice is a known weak pattern.' }
];

const MIN_LENGTH = 12;

/**
 * Validate a password. Returns { ok, errors[], warnings[], strength }.
 * Errors block submission; warnings are advisory.
 */
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

  // Simple strength heuristic: blends length and variety, capped at 5.
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

/* =========================================================
   Public-facing rules (sent to the client so the live hint UI matches)
   ========================================================= */

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
