require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const { v4: uuidv4 } = require('uuid');

const app = express();
const isProd = process.env.NODE_ENV === 'production';

// ── Supabase ──────────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── Security headers + HSTS ───────────────────────────────────────────────────
app.use(helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      mediaSrc: ["'self'"],
      connectSrc: ["'self'"],
    },
  },
}));

// ── CORS ──────────────────────────────────────────────────────────────────────
const allowedOrigin = process.env.CORS_ORIGIN || (!isProd ? 'http://localhost:3000' : null);
if (!allowedOrigin) {
  console.error('FATAL: CORS_ORIGIN environment variable is not set');
  process.exit(1);
}
app.use(cors({
  origin: allowedOrigin,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'X-Request-ID'],
}));

// ── Body parser ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));

// ── Request correlation ID ────────────────────────────────────────────────────
app.use((req, _res, next) => {
  req.requestId = req.headers['x-request-id'] || uuidv4();
  next();
});

// ── In-memory rate limiter (backup — DB rate limiting is primary) ─────────────
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});
app.use('/api/register', limiter);

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Normalize Nigerian phone to E.164.
 * Rejects non-Nigerian / unrecognised formats entirely.
 */
function normalizePhone(raw) {
  const digits = raw.replace(/\D/g, '');
  let normalized;

  if (digits.startsWith('234') && digits.length === 13) {
    normalized = '+' + digits;
  } else if (digits.startsWith('0') && digits.length === 11) {
    normalized = '+234' + digits.slice(1);
  } else if (digits.length === 10 && !digits.startsWith('0')) {
    normalized = '+234' + digits;
  } else {
    return null;
  }

  // Must match Nigerian mobile pattern: +234 [7|8|9][0|1] XXXXXXXX
  if (!/^\+234[789][01]\d{8}$/.test(normalized)) return null;
  return normalized;
}

/** Membership number always uppercase */
function normalizeMembership(raw) {
  return raw ? raw.trim().toUpperCase() : raw;
}

/** Validate name fields — letters, spaces, hyphens, apostrophes only */
function isValidName(value) {
  return /^[A-Za-z\s\-']+$/.test(value.trim());
}

// ── DB-based rate limiter (survives Vercel cold starts) ───────────────────────
async function isRateLimited(ip) {
  const windowStart = new Date(Date.now() - 15 * 60 * 1000).toISOString();
  const { count, error } = await supabase
    .from('reg_attempts')
    .select('*', { count: 'exact', head: true })
    .eq('ip_address', ip)
    .gte('attempted_at', windowStart);

  if (error) {
    console.error('Rate limit DB check failed, allowing through:', error.message);
    return false;
  }
  return count >= 10;
}

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    const { error } = await supabase.from('reg_counter').select('count').single();
    if (error) throw error;
    res.json({ status: 'ok', database: 'connected' });
  } catch {
    res.status(503).json({ status: 'error', database: 'unreachable' });
  }
});

// ── Registration ──────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const requestId = req.requestId;
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip || 'unknown';
  console.log(`[REG:${requestId}] Attempt from ${ip}`);

  // DB rate limit
  if (await isRateLimited(ip)) {
    console.warn(`[REG:${requestId}] Rate limited: ${ip}`);
    return res.status(429).json({ error: 'Too many attempts. Please wait 15 minutes.' });
  }

  // Destructure body
  const {
    surname,
    other_names,
    gender,
    telephone,
    apc_membership_no,
    availability,
    // optional
    lga,
    town,
    occupation,
    voters_card_no,
  } = req.body;

  // ── Required field presence check ─────────────────────────────────────────
  const required = { surname, other_names, gender, telephone, apc_membership_no, availability };
  const missing = Object.entries(required)
    .filter(([, v]) => !v || String(v).trim() === '')
    .map(([k]) => k);
  if (missing.length) {
    return res.status(400).json({ error: `Missing required fields: ${missing.join(', ')}` });
  }

  // ── surname validation ─────────────────────────────────────────────────────
  const surnameClean = surname.trim();
  if (surnameClean.length < 2) {
    return res.status(400).json({ error: 'Surname must be at least 2 characters.' });
  }
  if (!isValidName(surnameClean)) {
    return res.status(400).json({ error: 'Surname contains invalid characters.' });
  }

  // ── other_names validation ─────────────────────────────────────────────────
  const otherNamesClean = other_names.trim();
  if (otherNamesClean.length < 2) {
    return res.status(400).json({ error: 'Other names must be at least 2 characters.' });
  }
  if (!isValidName(otherNamesClean)) {
    return res.status(400).json({ error: 'Other names contains invalid characters.' });
  }

  // ── gender validation ──────────────────────────────────────────────────────
  const genderClean = gender.trim();
  if (!['Male', 'Female'].includes(genderClean)) {
    return res.status(400).json({ error: 'Gender must be Male or Female.' });
  }

  // ── telephone validation ───────────────────────────────────────────────────
  const normalizedPhone = normalizePhone(String(telephone).trim());
  if (!normalizedPhone) {
    return res.status(400).json({
      error: 'Invalid phone number. Please enter a valid Nigerian mobile number (e.g. 08012345678).',
    });
  }

  // ── apc_membership_no validation ──────────────────────────────────────────
  const membershipClean = String(apc_membership_no).trim();
  if (membershipClean.length < 5 || membershipClean.length > 50) {
    return res.status(400).json({ error: 'APC Membership Number must be between 5 and 50 characters.' });
  }
  const normalizedMembership = normalizeMembership(membershipClean);

  // ── availability validation ────────────────────────────────────────────────
  const availabilityClean = availability.trim();
  if (!['Yes', 'No'].includes(availabilityClean)) {
    return res.status(400).json({ error: 'Availability must be Yes or No.' });
  }

  // ── optional field length caps ─────────────────────────────────────────────
  if (lga && String(lga).trim().length > 100) {
    return res.status(400).json({ error: 'LGA must not exceed 100 characters.' });
  }
  if (town && String(town).trim().length > 100) {
    return res.status(400).json({ error: 'Town must not exceed 100 characters.' });
  }
  if (occupation && String(occupation).trim().length > 100) {
    return res.status(400).json({ error: 'Occupation must not exceed 100 characters.' });
  }
  if (voters_card_no && String(voters_card_no).trim().length > 50) {
    return res.status(400).json({ error: "Voter's Card Number must not exceed 50 characters." });
  }

  // ── Duplicate checks (phone, APC membership, voters card) ──────────────────
  const dupChecks = [
    { field: 'telephone',      value: normalizedPhone,      label: 'phone number' },
    { field: 'apc_membership_no', value: normalizedMembership, label: 'APC Membership Number' },
  ];
  if (voters_card_no?.trim()) {
    dupChecks.push({ field: 'voters_card_no', value: voters_card_no.trim(), label: "Voter's Card Number" });
  }

  for (const check of dupChecks) {
    const { data: existing, error: dupError } = await supabase
      .from('registrations')
      .select('id')
      .eq(check.field, check.value)
      .limit(1);

    if (dupError) {
      console.error(`[REG:${requestId}] Duplicate check error (${check.field}):`, dupError.message);
      return res.status(500).json({ error: isProd ? 'Server error.' : dupError.message });
    }
    if (existing && existing.length > 0) {
      return res.status(409).json({
        error: `This ${check.label} is already registered.`,
        field: check.field,
      });
    }
  }

  // ── Audit log (non-blocking) ───────────────────────────────────────────────
  supabase.from('reg_attempts').insert({
    ip_address: ip,
    phone: normalizedPhone,
    request_id: requestId,
    attempted_at: new Date().toISOString(),
  }).then(({ error: e }) => {
    if (e) console.error(`[REG:${requestId}] Audit insert failed:`, e.message);
  });

  // ── Get next reg code (atomic counter) ────────────────────────────────────
  const { data: reg_code, error: codeError } = await supabase.rpc('get_next_reg_code');
  if (codeError || !reg_code) {
    console.error(`[REG:${requestId}] Code gen failed:`, codeError?.message);
    return res.status(500).json({ error: isProd ? 'Server error.' : codeError?.message });
  }

  // ── Insert registration ────────────────────────────────────────────────────
  const { error: insertError } = await supabase.from('registrations').insert({
    reg_code,
    surname: surnameClean,
    other_names: otherNamesClean,
    gender: genderClean,
    telephone: normalizedPhone,
    apc_membership_no: normalizedMembership,
    availability: availabilityClean,
    lga: lga?.trim() || null,
    town: town?.trim() || null,
    occupation: occupation?.trim() || null,
    voters_card_no: voters_card_no?.trim() || null,
    ip_address: ip,
    request_id: requestId,
  });

  if (insertError) {
    // Race condition — concurrent duplicate hits unique constraint
    if (insertError.code === '23505') {
      const detail = insertError.message || '';
      let dupField = 'phone number';
      if (detail.includes('apc_membership_no')) dupField = 'APC Membership Number';
      else if (detail.includes('voters_card_no')) dupField = "Voter's Card Number";
      return res.status(409).json({ error: `This ${dupField} is already registered.` });
    }
    console.error(`[REG:${requestId}] Insert error:`, insertError.message);
    return res.status(500).json({ error: isProd ? 'Server error.' : insertError.message });
  }

  console.log(`[REG:${requestId}] Success — code: ${reg_code}`);
  return res.status(201).json({ success: true, reg_code, message: 'Registration successful!' });
});

// ── Serve frontend (public folder) ───────────────────────────────────────────
const path = require('path');
app.use(express.static(path.join(__dirname, '../public')));

// Serve index.html for any non-API route (SPA fallback)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ── 404 for unmatched API routes ──────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

// ── Global error handler ─────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error(`[ERROR] ${req.method} ${req.path}:`, err.message);
  res.status(500).json({ error: 'Internal server error.' });
});

// ── Local dev server (not used on Vercel) ─────────────────────────────────────
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`\n✅ Server running at http://localhost:${PORT}\n`);
  });
}

module.exports = app;