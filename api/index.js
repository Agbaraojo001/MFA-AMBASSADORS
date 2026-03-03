/**
 * api/index.js — MFA Ambassadors 2026 Registration API
 * ─────────────────────────────────────────────────────────────
 * Vercel Serverless Entry Point.
 * Exports the Express app — Vercel handles HTTP, no app.listen().
 *
 * Vercel fixes applied vs original server.js:
 *  ✅  No app.listen()     — Vercel is serverless, handles HTTP itself
 *  ✅  No process.exit()   — crashes a cold-start; replaced with 503 guard
 *  ✅  No startup DB check — no persistent boot phase; checked lazily
 *  ✅  Lazy Supabase client — created once, reused across warm invocations
 *  ✅  trust proxy = 1     — Vercel sits behind a proxy; needed for real IPs
 */

'use strict';

const express   = require('express');
const helmet    = require('helmet');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

// ── 0. ENV ────────────────────────────────────────────────────
const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const CORS_ORIGIN          = process.env.CORS_ORIGIN || '*';
const NODE_ENV             = process.env.NODE_ENV    || 'development';
const isProd               = NODE_ENV === 'production';
const configValid          = !!(SUPABASE_URL && SUPABASE_SERVICE_KEY);

if (!configValid) {
  console.error('[BOOT] Missing SUPABASE_URL or SUPABASE_SERVICE_KEY');
}

// ── 1. SUPABASE LAZY SINGLETON ────────────────────────────────
let _supabase = null;
function getSupabase() {
  if (!_supabase) {
    _supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
      auth: { persistSession: false },
      db:   { schema: 'public' },
      global: {
        fetch: (url, opts = {}) =>
          fetch(url, { ...opts, signal: AbortSignal.timeout(10_000) }),
      },
    });
  }
  return _supabase;
}

// ── 2. APP ────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1); // Required on Vercel: real client IP via x-forwarded-for

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],
      styleSrc:   ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:    ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:     ["'self'", 'data:'],
      connectSrc: ["'self'"],
    },
  },
}));

app.use(cors({
  origin:         CORS_ORIGIN === '*' ? '*' : CORS_ORIGIN.split(',').map(s => s.trim()),
  methods:        ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
}));

app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: true, limit: '50kb' }));

// ── 3. RATE LIMITERS ─────────────────────────────────────────
function makeLimiter(max, windowMs, message) {
  return rateLimit({
    windowMs, max,
    standardHeaders: true,
    legacyHeaders:   false,
    keyGenerator: req =>
      (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
      req.socket?.remoteAddress || 'unknown',
    handler: (_req, res) =>
      res.status(429).json({ success: false, code: 'RATE_LIMITED', message }),
  });
}

app.use(makeLimiter(100, 15 * 60 * 1000,
  'Too many requests. Please wait 15 minutes and try again.'));

const registrationLimiter = makeLimiter(5, 10 * 60 * 1000,
  'Too many registration attempts. Please wait 10 minutes before trying again.');

// ── 4. CONFIG GUARD ───────────────────────────────────────────
app.use((req, res, next) => {
  if (!configValid && req.path.startsWith('/api/')) {
    return res.status(503).json({
      success: false, code: 'MISCONFIGURED',
      message: 'Server is not properly configured. Please contact the administrator.',
    });
  }
  next();
});

// ── 5. VALIDATION HELPERS ────────────────────────────────────
function sanitise(raw) {
  if (typeof raw !== 'string') return '';
  return raw.trim()
    .replace(/<[^>]*>/g, '')
    .replace(/[<>"'`]/g,  '')
    .replace(/\s+/g,      ' ');
}

function normalisePhone(raw) {
  const digits = raw.replace(/[\s\-().+]/g, '');
  if (!/^\d+$/.test(digits))  throw new Error('Phone number must contain digits only.');
  if (digits.length < 7)      throw new Error('Phone number is too short.');
  if (digits.length > 15)     throw new Error('Phone number is too long.');
  if (digits.startsWith('0') && digits.length === 11)   return '+234' + digits.slice(1);
  if (digits.startsWith('234') && digits.length === 13) return '+' + digits;
  return '+' + digits;
}

function validateAndSanitise(body) {
  const errors = [];

  const surname = sanitise(body.surname ?? '');
  if (!surname)                    errors.push({ field:'surname', message:'Surname is required.' });
  else if (surname.length < 2)     errors.push({ field:'surname', message:'Surname must be at least 2 characters.' });
  else if (surname.length > 100)   errors.push({ field:'surname', message:'Surname must not exceed 100 characters.' });
  else if (!/^[a-zA-Z\s'\-.]+$/.test(surname))
    errors.push({ field:'surname', message:'Surname may only contain letters, spaces, hyphens, and apostrophes.' });

  const otherNames = sanitise(body.other_names ?? '');
  if (!otherNames)                    errors.push({ field:'other_names', message:'Other names are required.' });
  else if (otherNames.length < 2)     errors.push({ field:'other_names', message:'Other names must be at least 2 characters.' });
  else if (otherNames.length > 150)   errors.push({ field:'other_names', message:'Other names must not exceed 150 characters.' });
  else if (!/^[a-zA-Z\s'\-.]+$/.test(otherNames))
    errors.push({ field:'other_names', message:'Other names may only contain letters, spaces, hyphens, and apostrophes.' });

  const gender = sanitise(body.gender ?? '');
  if (!['Male','Female'].includes(gender))
    errors.push({ field:'gender', message:'Please select a valid gender.' });

  let telephone = '';
  const rawPhone = String(body.telephone ?? '').trim();
  if (!rawPhone) {
    errors.push({ field:'telephone', message:'Phone number is required.' });
  } else {
    try   { telephone = normalisePhone(rawPhone); }
    catch (e) { errors.push({ field:'telephone', message: e.message }); }
  }

  const availability = sanitise(body.availability ?? '');
  if (!['Yes','No'].includes(availability))
    errors.push({ field:'availability', message:'Please indicate whether you will attend.' });

  const lga        = sanitise(body.lga              ?? '');
  const town       = sanitise(body.town             ?? '');
  const occupation = sanitise(body.occupation       ?? '');
  const apcNo      = sanitise(body.apc_membership_no ?? '');
  const votersCard = sanitise(body.voters_card_no    ?? '');

  if (lga.length        > 100) errors.push({ field:'lga',              message:'LGA must not exceed 100 characters.' });
  if (town.length       > 100) errors.push({ field:'town',             message:'Town must not exceed 100 characters.' });
  if (occupation.length > 100) errors.push({ field:'occupation',       message:'Occupation must not exceed 100 characters.' });
  if (apcNo && !/^[a-zA-Z0-9\/\-_\s]{1,50}$/.test(apcNo))
    errors.push({ field:'apc_membership_no', message:'APC Membership No. contains invalid characters.' });
  if (votersCard && !/^[a-zA-Z0-9\s\-]{1,20}$/.test(votersCard))
    errors.push({ field:'voters_card_no', message:"Voter's Card No. contains invalid characters." });

  if (errors.length) {
    const err = new Error('Validation failed');
    err.name   = 'MultiValidationError';
    err.errors = errors;
    throw err;
  }

  return {
    surname, other_names: otherNames, gender, telephone, availability,
    lga:               lga        || null,
    town:              town       || null,
    occupation:        occupation || null,
    apc_membership_no: apcNo      || null,
    voters_card_no:    votersCard || null,
  };
}

// ── 6. ROUTES ─────────────────────────────────────────────────

// Health check — used by Vercel, uptime monitors, /api/health
app.get('/api/health', async (_req, res) => {
  try {
    const { error } = await getSupabase().from('reg_counter').select('current_val').limit(1);
    if (error) throw error;
    res.json({ status:'ok', database:'connected', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('[Health]', err.message);
    res.status(503).json({ status:'error', database:'unreachable' });
  }
});

// Registration
app.post('/api/register', registrationLimiter, async (req, res) => {
  const sb = getSupabase();

  // Step 1 — validate
  let cleanData;
  try {
    cleanData = validateAndSanitise(req.body);
  } catch (err) {
    if (err.name === 'MultiValidationError') {
      return res.status(422).json({
        success:false, code:'VALIDATION_ERROR',
        message:'Please correct the highlighted fields.', errors: err.errors,
      });
    }
    return res.status(422).json({ success:false, code:'VALIDATION_ERROR', message: err.message });
  }

  // Step 2 — duplicate phone check
  try {
    const { data: existing, error } = await sb
      .from('registrations').select('reg_code')
      .eq('telephone', cleanData.telephone).maybeSingle();
    if (error) throw error;
    if (existing) {
      return res.status(409).json({
        success:false, code:'DUPLICATE_PHONE',
        message:`This phone number is already registered. Your existing code is: ${existing.reg_code}`,
        reg_code: existing.reg_code,
      });
    }
  } catch (err) {
    console.error('[DB] Duplicate check:', err.message);
    return res.status(503).json({ success:false, code:'DATABASE_ERROR',
      message:'Could not verify your details. Please try again shortly.' });
  }

  // Step 3 — atomic code generation via PostgreSQL RPC
  let regCode;
  try {
    const { data, error } = await sb.rpc('get_next_reg_code');
    if (error) throw error;
    if (!data || typeof data !== 'string') throw new Error('Unexpected RPC value');
    regCode = data;
  } catch (err) {
    console.error('[DB] Code generation:', err.message);
    return res.status(503).json({ success:false, code:'CODE_GENERATION_ERROR',
      message:'Could not generate a registration code. Please try again.' });
  }

  // Step 4 — insert
  const ipAddress = (
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket?.remoteAddress || 'unknown'
  ).slice(0, 45);

  try {
    const { error } = await sb.from('registrations').insert({
      ...cleanData, reg_code: regCode, ip_address: ipAddress,
    });
    if (error) {
      if (error.code === '23505') {
        return res.status(409).json({ success:false, code:'CONFLICT',
          message:'A brief conflict occurred. Please try again.' });
      }
      if (error.code === '23514') {
        return res.status(422).json({ success:false, code:'VALIDATION_ERROR',
          message:'One or more field values were not accepted. Please review and resubmit.' });
      }
      throw error;
    }
  } catch (err) {
    console.error('[DB] Insert:', err.message);
    return res.status(503).json({ success:false, code:'DATABASE_ERROR',
      message:'Your information could not be saved. Please try again shortly.' });
  }

  // Step 5 — audit log (non-blocking)
  sb.from('reg_attempts').insert({ ip_address: ipAddress })
    .then(({ error }) => { if (error) console.warn('[Audit]', error.message); });

  // Step 6 — respond
  console.log(`[REG] ${regCode} | ${cleanData.surname}, ${cleanData.other_names}`);
  return res.status(201).json({
    success:true, code:'REGISTERED', message:'Registration successful.',
    reg_code: regCode,
    full_name: `${cleanData.other_names} ${cleanData.surname}`,
  });
});

// ── 7. ERROR MIDDLEWARE ───────────────────────────────────────
app.use((err, _req, res, _next) => {
  if (err.type === 'entity.parse.failed')
    return res.status(400).json({ success:false, code:'INVALID_JSON',
      message:'Request body could not be read. Please try again.' });
  if (err.type === 'entity.too.large')
    return res.status(413).json({ success:false, code:'PAYLOAD_TOO_LARGE',
      message:'Request is too large.' });
  console.error('[UNHANDLED]', err);
  res.status(500).json({ success:false, code:'INTERNAL_ERROR',
    message: isProd
      ? 'An unexpected error occurred. Please try again or contact the organisers.'
      : err.message });
});

app.use((_req, res) =>
  res.status(404).json({ success:false, code:'NOT_FOUND', message:'Route not found.' }));

// ── 8. EXPORT ─────────────────────────────────────────────────
// DO NOT call app.listen() — Vercel invokes this module directly.
module.exports = app;
