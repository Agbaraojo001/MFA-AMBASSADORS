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

// ── Security headers + HSTS (FIX #10) ────────────────────────────────────────
app.use(helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));

// ── CORS — FIX #1: crash on missing CORS_ORIGIN, never default to * ──────────
const allowedOrigin = process.env.CORS_ORIGIN;
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

// ── Request correlation ID — FIX #9 ──────────────────────────────────────────
app.use((req, _res, next) => {
  req.requestId = req.headers['x-request-id'] || uuidv4();
  next();
});

// ── In-memory rate limiter (backup only — see DB rate limiting below) ─────────
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
 * FIX #2: reject non-Nigerian / unrecognised formats entirely.
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

/** FIX #7: membership number always uppercase */
function normalizeMembership(raw) {
  return raw ? raw.trim().toUpperCase() : raw;
}

// ── DB-based rate limiter — FIX #6 (survives Vercel cold starts) ─────────────
async function isRateLimited(ip) {
  const windowStart = new Date(Date.now() - 15 * 60 * 1000).toISOString();
  const { count, error } = await supabase
    .from('reg_attempts')
    .select('*', { count: 'exact', head: true })
    .eq('ip_address', ip)
    .gte('attempted_at', windowStart);

  if (error) {
    console.error('Rate limit DB check failed, allowing through:', error.message);
    return false; // fail open — don't block legitimate users on DB hiccup
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
    full_name, email, phone, state, lga, ward,
    polling_unit, apc_membership_no, years_in_apc, occupation,
  } = req.body;

  // Required field check
  const required = { full_name, email, phone, state, lga, ward, polling_unit, years_in_apc };
  const missing = Object.entries(required)
    .filter(([, v]) => !v || String(v).trim() === '')
    .map(([k]) => k);
  if (missing.length) {
    return res.status(400).json({ error: `Missing required fields: ${missing.join(', ')}` });
  }

  // Email format
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return res.status(400).json({ error: 'Invalid email address.' });
  }

  // Phone — FIX #2
  const normalizedPhone = normalizePhone(String(phone).trim());
  if (!normalizedPhone) {
    return res.status(400).json({
      error: 'Invalid phone number. Please enter a valid Nigerian mobile number (e.g. 08012345678).',
    });
  }

  // Years in APC
  const yearsNum = parseInt(years_in_apc, 10);
  if (isNaN(yearsNum) || yearsNum < 0 || yearsNum > 50) {
    return res.status(400).json({ error: 'Years in APC must be between 0 and 50.' });
  }

  // Membership no — FIX #7
  const normalizedMembership = normalizeMembership(apc_membership_no);

  // Duplicate phone check
  const { data: existing, error: dupError } = await supabase
    .from('registrations')
    .select('id')
    .eq('phone', normalizedPhone)
    .maybeSingle();

  if (dupError) {
    console.error(`[REG:${requestId}] Duplicate check error:`, dupError.message);
    return res.status(500).json({ error: isProd ? 'Server error.' : dupError.message });
  }
  if (existing) {
    return res.status(409).json({ error: 'This phone number is already registered.' });
  }

  // Audit log (non-blocking) — FIX #6: now used for rate limiting too
  supabase.from('reg_attempts').insert({
    ip_address: ip,
    phone: normalizedPhone,
    request_id: requestId,
    attempted_at: new Date().toISOString(),
  }).then(({ error: e }) => {
    if (e) console.error(`[REG:${requestId}] Audit insert failed:`, e.message);
  });

  // Get next reg code (atomic counter)
  const { data: reg_code, error: codeError } = await supabase.rpc('get_next_reg_code');
  if (codeError || !reg_code) {
    console.error(`[REG:${requestId}] Code gen failed:`, codeError?.message);
    return res.status(500).json({ error: isProd ? 'Server error.' : codeError?.message });
  }

  // Insert registration
  const { error: insertError } = await supabase.from('registrations').insert({
    reg_code,
    full_name: full_name.trim(),
    email: email.trim().toLowerCase(),
    phone: normalizedPhone,
    state: state.trim(),
    lga: lga.trim(),
    ward: ward.trim(),
    polling_unit: polling_unit.trim(),
    apc_membership_no: normalizedMembership,
    years_in_apc: yearsNum,
    occupation: occupation?.trim() || null,
    ip_address: ip,
    request_id: requestId,
  });

  if (insertError) {
    // FIX #4: race condition — concurrent duplicate hits 23505
    if (insertError.code === '23505') {
      return res.status(409).json({ error: 'This phone number is already registered.' });
    }
    console.error(`[REG:${requestId}] Insert error:`, insertError.message);
    return res.status(500).json({ error: isProd ? 'Server error.' : insertError.message });
  }

  console.log(`[REG:${requestId}] Success — code: ${reg_code}`);
  return res.status(201).json({ success: true, reg_code, message: 'Registration successful!' });
});

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

module.exports = app;