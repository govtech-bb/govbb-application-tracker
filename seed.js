/**
 * Seed / initialise the database.
 *
 * Behaviour depends on NODE_ENV:
 *
 *   Development (default):
 *     - Upserts programmes, officers, API client (with the dev key).
 *     - Wipes applications/applicants/status_events/notifications and re-creates
 *       a small set of sample applications across every status.
 *
 *   Production (NODE_ENV=production):
 *     - Upserts programmes, officers, API client. NEVER touches application
 *       data — running this on a live deploy is safe.
 *     - Officer passwords come from OFFICER_PASSWORD_<USERNAME> env vars.
 *       If unset, a random password is generated and printed to logs ONCE
 *       so the first deploy isn't blocked. Save it.
 *     - API key comes from INCOMING_API_KEY env var. If unset, generates one
 *       and prints once.
 *
 * Run with:     node seed.js
 * Reset (dev):  npm run reset
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { db, insertStatusEvent } = require('./db');
const { generateUniqueCode } = require('./codes');
const { issueKey } = require('./apikey');

const IS_PROD = process.env.NODE_ENV === 'production';

const STATUSES = ['received','under_review','action_needed','approved','rejected','completed'];

const PROGRAMMES = [
  {
    code: 'BYAC',
    name: 'Barbados YouthADVANCE Corps',
    ministry: 'Ministry of Youth, Sport and Community Engagement',
    default_sla_days: 21,
    contact_email: 'byac@barbados.gov.bb',
    contact_phone: '(246) 535-6500'
  },
  {
    code: 'HIRED',
    name: 'Get Hired',
    ministry: 'Ministry of Youth, Sport and Community Engagement',
    default_sla_days: 14,
    contact_email: 'gethired@barbados.gov.bb',
    contact_phone: '(246) 535-6520'
  },
  {
    code: 'PATH',
    name: 'Pathways Employability Programme',
    ministry: 'Ministry of Youth, Sport and Community Engagement',
    default_sla_days: 14,
    contact_email: 'pathways@barbados.gov.bb',
    contact_phone: '(246) 535-6540'
  },
  {
    code: 'DMP',
    name: 'Digital Media Programme',
    ministry: 'Ministry of Youth, Sport and Community Engagement',
    default_sla_days: 21,
    contact_email: 'dmp@barbados.gov.bb',
    contact_phone: '(246) 535-6560'
  },
  {
    code: 'YES',
    name: 'Youth Entrepreneurship Scheme — First Contact',
    ministry: 'Ministry of Youth, Sport and Community Engagement',
    default_sla_days: 14,
    contact_email: 'yes@barbados.gov.bb',
    contact_phone: '(246) 535-6580'
  },
  {
    code: 'JOBSTART',
    name: 'Job Start Plus',
    ministry: 'Ministry of Youth, Sport and Community Engagement',
    default_sla_days: 21,
    contact_email: 'jobstart@barbados.gov.bb',
    contact_phone: '(246) 535-6600'
  }
];

// Officers are identified by email — that's their login. The optional
// `envKey` is just a stable handle for the OFFICER_PASSWORD_<KEY> env var
// and must not change between deploys (otherwise prod credentials get lost).
const OFFICERS = [
  { envKey: 'ANDREA', password: 'andrea',  name: 'Andrea Best',     email: 'andrea.best@barbados.gov.bb',     ministry: 'MYSCE', role: 'Senior YDP Officer',       is_admin: 1 },
  { envKey: 'TREVOR', password: 'trevor',  name: 'Trevor Inniss',   email: 'trevor.inniss@barbados.gov.bb',   ministry: 'MYSCE', role: 'YDP Officer',              is_admin: 0 },
  { envKey: 'JOY',    password: 'joy',     name: 'Joy Greenidge',   email: 'joy.greenidge@barbados.gov.bb',   ministry: 'MYSCE', role: 'YDP Programme Manager',    is_admin: 0 }
];

const APPLICANTS = [
  // Reference codes will be generated; seed picks programme + status + timeline.
  { programme: 'BYAC',     name: 'Kareem Walcott',       email: 'kareem.walcott@example.com',       phone: '(246) 555-0102',
    submittedAt: '2026-04-22 09:14',
    form_data: {
      date_of_birth: '2005-08-14',
      parish: 'St. Michael',
      national_registration_number: '050814-1234',
      highest_qualification: 'CXC CSEC – 7 subjects',
      areas_of_interest: ['Community development', 'Sports coaching', 'Mentoring'],
      availability: '6 months full-time',
      motivation: 'I want to give back to my community and learn skills that\nwill help me start a career in youth work.',
      has_criminal_record: false,
      emergency_contact: { name: 'Marcia Walcott', relationship: 'Mother', phone: '(246) 555-0202' }
    },
    timeline: [
      { at: '2026-04-22 09:14', status: 'received',     citizen_message: 'Application received and acknowledged.' },
      { at: '2026-04-25 11:02', status: 'under_review', citizen_message: 'An officer is now reviewing your application.', officer: 'andrea' }
    ],
    assignedTo: 'andrea'
  },
  { programme: 'HIRED',    name: 'Joelle Forde',         email: 'joelle.forde@example.com',         phone: '(246) 555-0103',
    submittedAt: '2026-05-01 14:30',
    form_data: {
      date_of_birth: '2001-03-22',
      parish: 'Christ Church',
      job_seeking_status: 'Unemployed for 6+ months',
      target_industries: ['Tourism and hospitality', 'Customer service'],
      cv_filename: 'Joelle_Forde_CV_2023.pdf',
      references: [
        { name: 'Yvonne Marshall', relationship: 'Former teacher', phone: '(246) 555-0301' },
        { name: 'David King', relationship: 'Mentor', phone: '(246) 555-0302' }
      ],
      open_to_relocation: false
    },
    timeline: [
      { at: '2026-05-01 14:30', status: 'received',      citizen_message: 'Application received.' },
      { at: '2026-05-03 10:15', status: 'under_review',  citizen_message: 'Reviewing your CV and references.', officer: 'andrea' },
      { at: '2026-05-05 16:48', status: 'action_needed', citizen_message: 'We need an updated CV. Please upload it via the link sent to your email.', officer: 'andrea',
        internal_note: 'CV submitted is from 2023; ask for current one.' }
    ],
    assignedTo: 'andrea'
  },
  { programme: 'PATH',     name: 'Anika Babb',           email: 'anika.babb@example.com',           phone: '(246) 555-0104',
    submittedAt: '2026-03-15 08:55',
    form_data: {
      date_of_birth: '2003-11-02',
      parish: 'St. Philip',
      current_status: 'Recent secondary school graduate',
      target_employability_skills: ['Digital literacy', 'Workplace communication', 'Financial literacy'],
      preferred_start_date: '2026-04-15',
      requires_transport_assistance: true
    },
    timeline: [
      { at: '2026-03-15 08:55', status: 'received',     citizen_message: 'Application received.' },
      { at: '2026-03-18 13:20', status: 'under_review', citizen_message: 'Officer reviewing supporting documents.', officer: 'trevor' },
      { at: '2026-04-02 09:40', status: 'approved',    citizen_message: 'Decision: approved. We will be in touch about your start date.', officer: 'trevor' }
    ],
    assignedTo: 'trevor'
  },
  { programme: 'BYAC',     name: 'Selwyn Greaves',       email: 'selwyn.greaves@example.com',       phone: '(246) 555-0105',
    submittedAt: '2026-05-07 17:11',
    form_data: {
      date_of_birth: '2006-01-19',
      parish: 'St. James',
      areas_of_interest: ['Environmental conservation', 'Cultural heritage'],
      availability: '3 months part-time'
    },
    timeline: [
      { at: '2026-05-07 17:11', status: 'received', citizen_message: 'Application received. We will assign an officer within 3 working days.' }
    ],
    assignedTo: null
  },
  { programme: 'DMP',      name: 'Trinity Ford',         email: 'trinity.ford@example.com',         phone: '(246) 555-0106',
    submittedAt: '2026-04-10 10:00',
    form_data: {
      date_of_birth: '2000-06-30',
      parish: 'St. Michael',
      portfolio_url: 'https://trinityford.work',
      tracks: ['Video production', 'Motion graphics'],
      software_proficiency: { adobe_premiere: 'Advanced', after_effects: 'Intermediate', davinci_resolve: 'Beginner' },
      brief_summary: 'Three years freelancing on small commercial videos\nfor local businesses. Looking to formalise skills and\nmove into longer-form documentary work.'
    },
    timeline: [
      { at: '2026-04-10 10:00', status: 'received',     citizen_message: 'Application received.' },
      { at: '2026-04-12 14:22', status: 'under_review', citizen_message: 'Reviewing your portfolio submission.', officer: 'trevor' },
      { at: '2026-04-18 11:05', status: 'approved',    citizen_message: 'Decision: approved. Welcome to the cohort.', officer: 'trevor' },
      { at: '2026-04-25 09:30', status: 'completed',   citizen_message: 'You have started the programme. This case is closed.', officer: 'trevor' }
    ],
    assignedTo: 'trevor'
  },
  { programme: 'YES',      name: 'Marlon Best',          email: 'marlon.best@example.com',          phone: '(246) 555-0107',
    submittedAt: '2026-02-12 12:00',
    form_data: {
      date_of_birth: '1999-09-09',
      parish: 'St. Lucy',
      business_idea: 'Door-to-door fresh fish delivery from Six Men\'s Bay\nto St. James and St. Michael with cold-chain handling.',
      stage: 'Concept only',
      capital_required_bbd: 18500,
      has_business_plan: false,
      previous_business_experience: false
    },
    timeline: [
      { at: '2026-02-12 12:00', status: 'received',     citizen_message: 'Application received.' },
      { at: '2026-02-20 09:18', status: 'under_review', citizen_message: 'Reviewing your business concept.', officer: 'trevor' },
      { at: '2026-03-04 15:55', status: 'rejected',    citizen_message: 'Decision: not approved. Your concept did not meet the eligibility criteria. You can re-apply with a revised concept after 6 months.', officer: 'trevor' }
    ],
    assignedTo: 'trevor'
  },
  { programme: 'JOBSTART', name: 'Shenika Phillips',     email: 'shenika.phillips@example.com',     phone: '(246) 555-0108',
    submittedAt: '2026-04-30 09:30',
    form_data: {
      date_of_birth: '2002-07-12',
      parish: 'St. George',
      employment_history: [
        { employer: 'Nation Restaurants', role: 'Server', from: '2023-08', to: '2024-06' },
        { employer: 'Independence Foods', role: 'Cashier', from: '2024-07', to: '2025-12' }
      ],
      target_role: 'Administrative assistant',
      computer_skills_self_rating: 'Comfortable',
      requires_childcare_support: true
    },
    timeline: [
      { at: '2026-04-30 09:30', status: 'received',     citizen_message: 'Application received.' },
      { at: '2026-05-02 14:00', status: 'under_review', citizen_message: 'Officer reviewing your application.', officer: 'joy' }
    ],
    assignedTo: 'joy'
  }
];

/* =========================================================
   Run
   ========================================================= */

console.log(`Seeding GovBB tracker pilot database${IS_PROD ? ' (production mode)' : ''}...`);

if (!IS_PROD) {
  // Dev only: wipe application data so the seed is reproducible.
  db.exec(`
    DELETE FROM notifications;
    DELETE FROM status_events;
    DELETE FROM applications;
    DELETE FROM applicants;
  `);
} else {
  console.log('  · production mode — application data is NOT touched.');
}

// Programmes
const upsertProgramme = db.prepare(`
  INSERT INTO programmes (code, name, ministry, default_sla_days, allowed_statuses, contact_email, contact_phone)
  VALUES (@code, @name, @ministry, @default_sla_days, @allowed_statuses, @contact_email, @contact_phone)
  ON CONFLICT(code) DO UPDATE SET
    name = excluded.name,
    ministry = excluded.ministry,
    default_sla_days = excluded.default_sla_days,
    allowed_statuses = excluded.allowed_statuses,
    contact_email = excluded.contact_email,
    contact_phone = excluded.contact_phone
`);

for (const p of PROGRAMMES) {
  upsertProgramme.run({
    ...p,
    allowed_statuses: JSON.stringify(STATUSES)
  });
}
console.log(`  ✓ ${PROGRAMMES.length} programmes`);

// Officers — upserts password (when supplied), name/email/ministry/role,
// AND is_admin/is_active so the role assignment in the seed always wins.
// `username` is set to email (login identifier).
const upsertOfficerWithPassword = db.prepare(`
  INSERT INTO officers (username, password_hash, name, email, ministry, role, is_admin, is_active)
  VALUES (@email, @password_hash, @name, @email, @ministry, @role, @is_admin, 1)
  ON CONFLICT(username) DO UPDATE SET
    password_hash = excluded.password_hash,
    username = excluded.username,
    name = excluded.name,
    email = excluded.email,
    ministry = excluded.ministry,
    role = excluded.role,
    is_admin = excluded.is_admin,
    is_active = 1
`);
const updateOfficerNoPassword = db.prepare(`
  UPDATE officers
     SET username = @email, name = @name, email = @email, ministry = @ministry, role = @role,
         is_admin = @is_admin, is_active = 1
   WHERE email = @email OR username = @legacy_username
`);

const officerIds = {};
const generatedPasswords = []; // for printing at the end in prod
for (const o of OFFICERS) {
  let plaintext = o.password;
  // Find the existing row by email OR by the legacy short username (e.g. 'andrea')
  // so this seed is back-compat with pre-email-login databases.
  const legacyUsername = o.envKey.toLowerCase();
  const existing = db.prepare('SELECT id FROM officers WHERE email = ? OR username = ?').get(o.email, legacyUsername);

  if (IS_PROD) {
    const envVar = 'OFFICER_PASSWORD_' + o.envKey;
    plaintext = process.env[envVar];
    if (!plaintext) {
      if (existing) {
        // Existing row + no override: leave the password alone, just refresh metadata.
        plaintext = null;
      } else {
        plaintext = 'pw_' + crypto.randomBytes(9).toString('base64url');
        generatedPasswords.push({ email: o.email, password: plaintext });
      }
    }
  }
  if (plaintext) {
    upsertOfficerWithPassword.run({
      email: o.email,
      password_hash: bcrypt.hashSync(plaintext, 10),
      name: o.name,
      ministry: o.ministry,
      role: o.role,
      is_admin: o.is_admin || 0
    });
  } else {
    updateOfficerNoPassword.run({
      email: o.email,
      legacy_username: legacyUsername,
      name: o.name,
      ministry: o.ministry,
      role: o.role,
      is_admin: o.is_admin || 0
    });
  }
  const row = db.prepare('SELECT id FROM officers WHERE email = ?').get(o.email);
  if (row) officerIds[legacyUsername] = row.id;
}
console.log(`  ✓ ${OFFICERS.length} officers (Andrea is admin) — login with email address`);

// Programme assignments: every active officer gets every active programme by
// default. Idempotent — INSERT OR IGNORE skips rows that already exist.
const assign = db.prepare(`
  INSERT OR IGNORE INTO officer_programmes (officer_id, programme_id, granted_by_officer_id)
  VALUES (?, ?, NULL)
`);
const allProgrammeIds = db.prepare('SELECT id FROM programmes').all().map(r => r.id);
const allOfficerIds = db.prepare('SELECT id FROM officers WHERE is_active = 1').all().map(r => r.id);
let assignmentCount = 0;
for (const oid of allOfficerIds) {
  for (const pid of allProgrammeIds) {
    const r = assign.run(oid, pid);
    assignmentCount += r.changes;
  }
}
if (assignmentCount > 0) {
  console.log(`  ✓ ${assignmentCount} new programme assignments (officer × programme)`);
}

// Applications
const insertApplicant = db.prepare(`
  INSERT INTO applicants (name, email, phone) VALUES (?, ?, ?)
`);
const insertApplication = db.prepare(`
  INSERT INTO applications (code, programme_id, applicant_id, current_status, current_status_at, assigned_officer_id, form_data, created_at)
  VALUES (@code, @programme_id, @applicant_id, @current_status, @current_status_at, @assigned_officer_id, @form_data, @created_at)
`);
const insertEventRaw = db.prepare(`
  INSERT INTO status_events (application_id, status, citizen_message, internal_note, by_officer_id, created_at)
  VALUES (@application_id, @status, @citizen_message, @internal_note, @by_officer_id, @created_at)
`);

if (!IS_PROD) {
  // Dev only: insert sample applications.
  for (const a of APPLICANTS) {
    const programme = db.prepare('SELECT id FROM programmes WHERE code = ?').get(a.programme);
    if (!programme) { console.error(`Skip ${a.name}: unknown programme ${a.programme}`); continue; }

    const applicantId = insertApplicant.run(a.name, a.email, a.phone).lastInsertRowid;
    const code = generateUniqueCode(db, a.programme);
    const last = a.timeline[a.timeline.length - 1];

    const appId = insertApplication.run({
      code,
      programme_id: programme.id,
      applicant_id: applicantId,
      current_status: last.status,
      current_status_at: last.at,
      assigned_officer_id: a.assignedTo ? officerIds[a.assignedTo] : null,
      form_data: JSON.stringify(a.form_data || {}),
      created_at: a.submittedAt
    }).lastInsertRowid;

    for (const ev of a.timeline) {
      insertEventRaw.run({
        application_id: appId,
        status: ev.status,
        citizen_message: ev.citizen_message || null,
        internal_note: ev.internal_note || null,
        by_officer_id: ev.officer ? officerIds[ev.officer] : null,
        created_at: ev.at
      });
    }

    console.log(`  ✓ ${code}  ${a.programme.padEnd(8)}  ${a.name.padEnd(22)}  → ${last.status}`);
  }
}

// API client. In dev: fixed key, recreated each run. In prod: env-supplied
// or generated once on first run.
let issuedClient;
if (IS_PROD) {
  const existing = db.prepare(`SELECT id FROM api_clients WHERE name = ?`)
    .get('alpha.gov.bb forms processor');
  if (!existing) {
    const supplied = process.env.INCOMING_API_KEY;
    issuedClient = issueKey('alpha.gov.bb forms processor', 'webhooks:form-submitted', supplied);
  }
} else {
  db.prepare('DELETE FROM api_clients').run();
  const DEV_KEY_PLAINTEXT = 'dev-key-alpha-gov-bb-forms-DO-NOT-USE-IN-PROD';
  issuedClient = issueKey('alpha.gov.bb forms processor (dev)', 'webhooks:form-submitted', DEV_KEY_PLAINTEXT);
}

console.log(`\n  ✓ ${IS_PROD ? 'API client checked' : '1 API client (dev)'}`);

if (IS_PROD) {
  console.log('\nDone. Production seed complete.');
  if (generatedPasswords.length) {
    console.log('\n=================================================================');
    console.log('  Random officer passwords were generated. SAVE THESE NOW:');
    for (const { email, password } of generatedPasswords) {
      console.log(`    ${email}: ${password}`);
    }
    console.log('  These are bootstrap passwords only — officers should sign in once,');
    console.log('  then a password reset can be sent through the admin Users tab.');
    console.log('  Set OFFICER_PASSWORD_<ENVKEY> env vars (ANDREA/TREVOR/JOY) next');
    console.log('  time to control them.');
    console.log('=================================================================');
  }
  if (issuedClient && !process.env.INCOMING_API_KEY) {
    console.log('\n=================================================================');
    console.log('  An API key for the alpha.gov.bb forms processor was generated.');
    console.log('  SAVE THIS NOW — it cannot be recovered:');
    console.log(`    ${issuedClient.plaintext}`);
    console.log('  Set INCOMING_API_KEY in your env to control it next time.');
    console.log('=================================================================');
  }
} else {
  console.log('\nDone. Try:');
  console.log('  npm start');
  console.log('  open http://localhost:3030');
  console.log('\nOfficer logins (email + dev password):');
  console.log('  andrea.best@barbados.gov.bb / andrea       (admin)');
  console.log('  trevor.inniss@barbados.gov.bb / trevor');
  console.log('  joy.greenidge@barbados.gov.bb / joy');
  console.log('\nForm-intake API key (dev only):');
  console.log(`  X-API-Key: ${issuedClient.plaintext}`);
  console.log('  Used by /api/webhooks/form-submitted. Rotate by re-running this script.');
}
