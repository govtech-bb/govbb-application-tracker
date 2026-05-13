const crypto = require('crypto');

const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

function randomChar() {
  return ALPHABET[crypto.randomInt(ALPHABET.length)];
}

function generateCode(programmeCode, year = new Date().getFullYear()) {
  let suffix = '';
  for (let i = 0; i < 7; i++) suffix += randomChar();
  return `${programmeCode}-${year}-${suffix}`;
}

async function generateUniqueCode(pool, programmeCode) {
  for (let attempt = 0; attempt < 10; attempt++) {
    const code = generateCode(programmeCode);
    const { rows } = await pool.query('SELECT 1 FROM applications WHERE code = $1', [code]);
    if (rows.length === 0) return code;
  }
  let suffix = '';
  for (let i = 0; i < 11; i++) suffix += randomChar();
  return `${programmeCode}-${new Date().getFullYear()}-${suffix}`;
}

module.exports = { generateCode, generateUniqueCode };
