#!/usr/bin/env node
const { rotateKey } = require('./apikey');
const { pool } = require('./db');

const CLIENT_NAME = process.env.API_CLIENT_NAME || 'alpha.gov.bb forms processor';
const newKey = process.argv[2] || null;

(async () => {
  try {
    const result = await rotateKey(CLIENT_NAME, newKey);
    console.log('\n  API key rotated successfully.');
    console.log(`  Client:    ${result.name}`);
    console.log(`  New key:   ${result.plaintext}`);
    console.log('\n  Update INCOMING_API_KEY in your deployment env and on the sending side.\n');
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
})();
