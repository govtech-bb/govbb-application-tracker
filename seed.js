const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { pool, initDb, insertStatusEvent } = require('./db');
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

const OFFICERS = [
  { envKey: 'ANDREA', password: 'andrea',  name: 'Andrea Best',     email: 'andrea.best@barbados.gov.bb',     ministry: 'MYSCE', role: 'Senior YDP Officer',       is_admin: 1 },
  { envKey: 'TREVOR', password: 'trevor',  name: 'Trevor Inniss',   email: 'trevor.inniss@barbados.gov.bb',   ministry: 'MYSCE', role: 'YDP Officer',              is_admin: 0 },
  { envKey: 'JOY',    password: 'joy',     name: 'Joy Greenidge',   email: 'joy.greenidge@barbados.gov.bb',   ministry: 'MYSCE', role: 'YDP Programme Manager',    is_admin: 0 }
];

const APPLICANTS = [
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

async function seed() {
  const dbUrl = process.env.DATABASE_URL || 'postgresql://localhost:5432/govbb_tracker';
  console.log(`Connecting to: ${dbUrl.replace(/\/\/([^:]+):([^@]+)@/, '//$1:***@')}`);
  await initDb();

  console.log(`Seeding GovBB tracker pilot database${IS_PROD ? ' (production mode)' : ''}...`);

  if (!IS_PROD) {
    await pool.query(`
      DELETE FROM uploads;
      DELETE FROM notifications;
      DELETE FROM status_events;
      DELETE FROM applications;
      DELETE FROM applicants;
    `);
  } else {
    console.log('  · production mode — application data is NOT touched.');
  }

  // Programmes
  for (const p of PROGRAMMES) {
    await pool.query(`
      INSERT INTO programmes (code, name, ministry, default_sla_days, allowed_statuses, contact_email, contact_phone)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT(code) DO UPDATE SET
        name = EXCLUDED.name,
        ministry = EXCLUDED.ministry,
        default_sla_days = EXCLUDED.default_sla_days,
        allowed_statuses = EXCLUDED.allowed_statuses,
        contact_email = EXCLUDED.contact_email,
        contact_phone = EXCLUDED.contact_phone
    `, [p.code, p.name, p.ministry, p.default_sla_days, JSON.stringify(STATUSES), p.contact_email, p.contact_phone]);
  }
  console.log(`  ✓ ${PROGRAMMES.length} programmes`);

  // Officers
  const officerIds = {};
  const generatedPasswords = [];
  for (const o of OFFICERS) {
    let plaintext = o.password;
    const legacyUsername = o.envKey.toLowerCase();
    const { rows: existRows } = await pool.query(
      'SELECT id FROM officers WHERE email = $1 OR username = $2', [o.email, legacyUsername]
    );
    const existing = existRows[0];

    if (IS_PROD) {
      const envVar = 'OFFICER_PASSWORD_' + o.envKey;
      plaintext = process.env[envVar];
      if (!plaintext) {
        if (existing) {
          plaintext = null;
        } else {
          plaintext = 'pw_' + crypto.randomBytes(9).toString('base64url');
          generatedPasswords.push({ email: o.email, password: plaintext });
        }
      }
    }
    if (plaintext) {
      await pool.query(`
        INSERT INTO officers (username, password_hash, name, email, ministry, role, is_admin, is_active)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 1)
        ON CONFLICT(username) DO UPDATE SET
          password_hash = EXCLUDED.password_hash,
          username = EXCLUDED.username,
          name = EXCLUDED.name,
          email = EXCLUDED.email,
          ministry = EXCLUDED.ministry,
          role = EXCLUDED.role,
          is_admin = EXCLUDED.is_admin,
          is_active = 1
      `, [o.email, bcrypt.hashSync(plaintext, 10), o.name, o.email, o.ministry, o.role, o.is_admin || 0]);
    } else {
      await pool.query(`
        UPDATE officers
        SET username = $1, name = $2, email = $3, ministry = $4, role = $5,
            is_admin = $6, is_active = 1
        WHERE email = $1 OR username = $7
      `, [o.email, o.name, o.email, o.ministry, o.role, o.is_admin || 0, legacyUsername]);
    }
    const { rows: idRows } = await pool.query('SELECT id FROM officers WHERE email = $1', [o.email]);
    if (idRows[0]) officerIds[legacyUsername] = idRows[0].id;
  }
  console.log(`  ✓ ${OFFICERS.length} officers (Andrea is admin) — login with email address`);

  // Programme assignments
  const { rows: allProgrammeRows } = await pool.query('SELECT id FROM programmes');
  const allProgrammeIds = allProgrammeRows.map(r => r.id);
  const { rows: allOfficerRows } = await pool.query('SELECT id FROM officers WHERE is_active = 1');
  const allOfficerIds = allOfficerRows.map(r => r.id);
  let assignmentCount = 0;
  for (const oid of allOfficerIds) {
    for (const pid of allProgrammeIds) {
      const r = await pool.query(`
        INSERT INTO officer_programmes (officer_id, programme_id, granted_by_officer_id)
        VALUES ($1, $2, NULL)
        ON CONFLICT DO NOTHING
      `, [oid, pid]);
      assignmentCount += r.rowCount;
    }
  }
  if (assignmentCount > 0) {
    console.log(`  ✓ ${assignmentCount} new programme assignments (officer × programme)`);
  }

  // Applications
  if (!IS_PROD) {
    for (const a of APPLICANTS) {
      const { rows: progRows } = await pool.query('SELECT id FROM programmes WHERE code = $1', [a.programme]);
      const programme = progRows[0];
      if (!programme) { console.error(`Skip ${a.name}: unknown programme ${a.programme}`); continue; }

      const { rows: appRows } = await pool.query(
        'INSERT INTO applicants (name, email, phone) VALUES ($1, $2, $3) RETURNING id',
        [a.name, a.email, a.phone]
      );
      const applicantId = appRows[0].id;
      const code = await generateUniqueCode(pool, a.programme);
      const last = a.timeline[a.timeline.length - 1];

      const { rows: insertRows } = await pool.query(`
        INSERT INTO applications (code, programme_id, applicant_id, current_status, current_status_at, assigned_officer_id, form_data, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id
      `, [code, programme.id, applicantId, last.status, last.at,
          a.assignedTo ? officerIds[a.assignedTo] : null,
          JSON.stringify(a.form_data || {}), a.submittedAt]);
      const appId = insertRows[0].id;

      for (const ev of a.timeline) {
        await pool.query(`
          INSERT INTO status_events (application_id, status, citizen_message, internal_note, by_officer_id, created_at)
          VALUES ($1, $2, $3, $4, $5, $6)
        `, [appId, ev.status, ev.citizen_message || null, ev.internal_note || null,
            ev.officer ? officerIds[ev.officer] : null, ev.at]);
      }

      console.log(`  ✓ ${code}  ${a.programme.padEnd(8)}  ${a.name.padEnd(22)}  → ${last.status}`);
    }
  }

  // API client
  let issuedClient;
  if (IS_PROD) {
    const { rows: apiRows } = await pool.query(
      `SELECT id FROM api_clients WHERE name = $1`, ['alpha.gov.bb forms processor']
    );
    if (apiRows.length === 0) {
      const supplied = process.env.INCOMING_API_KEY;
      issuedClient = await issueKey('alpha.gov.bb forms processor', 'webhooks:form-submitted', supplied);
    }
  } else {
    await pool.query('DELETE FROM api_clients');
    const DEV_KEY_PLAINTEXT = 'dev-key-alpha-gov-bb-forms-DO-NOT-USE-IN-PROD';
    issuedClient = await issueKey('alpha.gov.bb forms processor (dev)', 'webhooks:form-submitted', DEV_KEY_PLAINTEXT);
  }

  console.log(`\n  ✓ ${IS_PROD ? 'API client checked' : '1 API client (dev)'}`);

  if (IS_PROD) {
    console.log('\nDone. Production seed complete.');
    if (generatedPasswords.length) {
      const credsPath = path.join(process.env.TRACKER_DATA_DIR || '.', '.bootstrap-credentials');
      const fd = fs.openSync(credsPath, 'w', 0o600);
      for (const cred of generatedPasswords) {
        fs.writeSync(fd, cred.email + ': ' + cred.password + '\n');
      }
      fs.closeSync(fd);
      console.log('\n=================================================================');
      console.log('  Random officer passwords were generated.');
      console.log(`  Written to: ${credsPath} (mode 600)`);
      console.log('  Read that file, save the credentials, then delete it.');
      console.log('  Set OFFICER_PASSWORD_<ENVKEY> env vars next time to control them.');
      console.log('=================================================================');
    }
    if (issuedClient && !process.env.INCOMING_API_KEY) {
      const keyPath = path.join(process.env.TRACKER_DATA_DIR || '.', '.bootstrap-api-key');
      fs.writeFileSync(keyPath, issuedClient.plaintext + '\n', { mode: 0o600 });
      console.log('\n=================================================================');
      console.log('  An API key for the alpha.gov.bb forms processor was generated.');
      console.log(`  Written to: ${keyPath} (mode 600)`);
      console.log('  Read that file, save the key, then delete it.');
      console.log('  Set INCOMING_API_KEY in your env to control it next time.');
      console.log('=================================================================');
    }
  } else {
    const devCredsPath = path.join('.', '.dev-credentials');
    const devLines = [
      'Officer logins (email + dev password):',
      '  andrea.best@barbados.gov.bb / andrea       (admin)',
      '  trevor.inniss@barbados.gov.bb / trevor',
      '  joy.greenidge@barbados.gov.bb / joy',
      '',
      'Form-intake API key (dev only):',
      `  X-API-Key: ${issuedClient.plaintext}`,
      '  Used by /api/webhooks/form-submitted. Rotate by re-running this script.'
    ];
    fs.writeFileSync(devCredsPath, devLines.join('\n') + '\n', { mode: 0o600 });
    console.log('\nDone. Try:');
    console.log('  npm start');
    console.log('  open http://localhost:3030');
    console.log(`\nDev credentials written to: ${devCredsPath}`);
  }

  await pool.end();
}

seed().catch(e => {
  console.error('Seed failed:', e);
  process.exit(1);
});
