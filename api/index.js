require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const express = require('express');
const cors    = require('cors');
const helmet  = require('helmet');
const rateLimit = require('express-rate-limit');
const path    = require('path');
const { createClient } = require('@supabase/supabase-js');
const { v4: uuidv4 }   = require('uuid');

const app    = express();
const isProd = process.env.NODE_ENV === 'production';

// ── Supabase ──────────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── Security headers ──────────────────────────────────────────────────────────
app.use(helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'"],
      styleSrc:    ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:     ["'self'", "https://fonts.gstatic.com"],
      imgSrc:      ["'self'", "data:", "https:"],
      mediaSrc:    ["'self'"],
      connectSrc:  ["'self'"],
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
  origin:         allowedOrigin,
  methods:        ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'X-Request-ID'],
}));

// ── Body parser ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));

// ── Registration gate ─────────────────────────────────────────────────────────
// Read per-request so Vercel picks up env changes without cold-start issues.
// To CLOSE: set REGISTRATION_OPEN=false in Vercel env vars → redeploy
// To REOPEN: set REGISTRATION_OPEN=true  in Vercel env vars → redeploy
const CLOSED_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MFA Ambassadors — Portal Temporarily Closed</title>
<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700;800;900&family=Open+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
  :root {
    --blue-deep: #0A1172; --blue-mid: #0D47A1; --cyan: #00BCD4;
    --green-ng: #008751; --cream: #FAFAFA; --muted: #5C6370;
    --border: rgba(13,71,161,0.12);
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Open Sans', sans-serif; background: #E8EAF6;
    min-height: 100vh; display: flex; align-items: center;
    justify-content: center; padding: 24px;
  }
  .card {
    background: var(--cream); box-shadow: 0 8px 40px rgba(10,17,114,0.15);
    border-radius: 2px; width: 100%; max-width: 560px;
    overflow: hidden; text-align: center;
  }
  .tribar { display: flex; height: 6px; }
  .tribar span:nth-child(1) { flex: 1; background: var(--green-ng); }
  .tribar span:nth-child(2) { flex: 1; background: #fff; border-top: 1px solid #ddd; }
  .tribar span:nth-child(3) { flex: 1; background: var(--green-ng); }
  .inner { padding: 52px 44px 56px; }
  .icon-wrap {
    width: 72px; height: 72px; border-radius: 50%;
    background: linear-gradient(135deg, var(--blue-deep), var(--blue-mid));
    display: flex; align-items: center; justify-content: center;
    margin: 0 auto 28px; box-shadow: 0 6px 24px rgba(10,17,114,0.25);
  }
  .icon-wrap svg { width: 34px; height: 34px; fill: none; stroke: var(--cyan); stroke-width: 2.2; stroke-linecap: round; stroke-linejoin: round; }
  .badge {
    display: inline-block; padding: 4px 16px; background: var(--blue-deep);
    color: var(--cyan); font-family: 'Montserrat', sans-serif; font-size: 9px;
    font-weight: 700; letter-spacing: 3px; text-transform: uppercase;
    border-radius: 20px; margin-bottom: 20px;
  }
  h1 {
    font-family: 'Montserrat', sans-serif; font-size: 20px; font-weight: 800;
    color: var(--blue-deep); text-transform: uppercase; letter-spacing: 0.5px;
    line-height: 1.35; margin-bottom: 24px;
  }
  .divider {
    width: 48px; height: 3px;
    background: linear-gradient(90deg, var(--green-ng), var(--cyan));
    border-radius: 2px; margin: 0 auto 24px;
  }
  .message { font-size: 15px; color: #2c2c2c; line-height: 1.8; max-width: 420px; margin: 0 auto; }
  .message .salutation { font-weight: 600; color: var(--blue-deep); display: block; margin-bottom: 12px; }
  .message .highlight { font-weight: 600; color: var(--blue-mid); }
  .footer-note { margin-top: 36px; padding-top: 24px; border-top: 1px solid var(--border); font-size: 12px; color: var(--muted); line-height: 1.6; }
  @media (max-width: 480px) { .inner { padding: 40px 24px 44px; } h1 { font-size: 17px; } }
</style>
</head>
<body>
  <div class="card">
    <div class="tribar"><span></span><span></span><span></span></div>
    <div class="inner">
      <div class="icon-wrap">
        <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
      </div>
      <div class="badge">MFA Ambassadors · 2026</div>
      <h1>Endorsement Registration Portal</h1>
      <div class="divider"></div>
      <div class="message">
        <span class="salutation">Dear Prospective Attendee,</span>
        Due to an <span class="highlight">overwhelming response</span>, our portal is temporarily closed.<br><br>
        Thank you for your <span class="highlight">amazing support</span> — stay tuned for further updates!
      </div>
      <div class="footer-note">
        MFA Ambassadors &nbsp;·&nbsp; Endorsement Drive 2026<br>
        Further announcements will be communicated through official channels.
      </div>
    </div>
    <div class="tribar"><span></span><span></span><span></span></div>
  </div>
</body>
</html>`;

app.use((req, res, next) => {
  // Read env var per-request — works reliably on Vercel serverless
  const isOpen = process.env.REGISTRATION_OPEN === 'true';
  if (isOpen) return next();

  // Always let health checks through
  if (req.path === '/api/health') return next();

  // API calls get a JSON 503
  if (req.path.startsWith('/api/')) {
    return res.status(503).json({ error: 'Registration is currently closed.' });
  }

  // All browser/HTML routes get the inline closed page
  res.status(503).setHeader('Content-Type', 'text/html').send(CLOSED_HTML);
});

// ── Request correlation ID ────────────────────────────────────────────────────
app.use((req, _res, next) => {
  req.requestId = req.headers['x-request-id'] || uuidv4();
  next();
});

// ── In-memory rate limiter ────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs:       60 * 60 * 1000,
  max:            200,
  standardHeaders: true,
  legacyHeaders:  false,
  message:        { error: 'Too many requests, please try again later.' },
});
app.use('/api/register', limiter);

// ── Helpers ───────────────────────────────────────────────────────────────────
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

  if (!/^\+234[789][01]\d{8}$/.test(normalized)) return null;
  return normalized;
}

function normalizeMembership(raw) {
  return raw ? raw.trim().toUpperCase() : raw;
}

function isValidName(value) {
  return /^[A-Za-z\s\-']+$/.test(value.trim());
}

// ── DB-based rate limiter ─────────────────────────────────────────────────────
async function isRateLimited(ip) {
  const windowStart = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const { count, error } = await supabase
    .from('reg_attempts')
    .select('*', { count: 'exact', head: true })
    .eq('ip_address', ip)
    .gte('attempted_at', windowStart);

  if (error) {
    console.error('Rate limit DB check failed, allowing through:', error.message);
    return false;
  }
  return count >= 200;
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

  if (await isRateLimited(ip)) {
    console.warn(`[REG:${requestId}] Rate limited: ${ip}`);
    return res.status(429).json({ error: 'Too many attempts. Please wait an hour before trying again.' });
  }

  const {
    surname, other_names, gender, telephone,
    apc_membership_no, availability,
    lga, town, occupation, voters_card_no,
  } = req.body;

  const required = { surname, other_names, gender, telephone, availability };
  const missing  = Object.entries(required)
    .filter(([, v]) => !v || String(v).trim() === '')
    .map(([k]) => k);
  if (missing.length) {
    return res.status(400).json({ error: `Missing required fields: ${missing.join(', ')}` });
  }

  const surnameClean = surname.trim();
  if (surnameClean.length < 2)    return res.status(400).json({ error: 'Surname must be at least 2 characters.' });
  if (!isValidName(surnameClean)) return res.status(400).json({ error: 'Surname contains invalid characters.' });

  const otherNamesClean = other_names.trim();
  if (otherNamesClean.length < 2)    return res.status(400).json({ error: 'Other names must be at least 2 characters.' });
  if (!isValidName(otherNamesClean)) return res.status(400).json({ error: 'Other names contains invalid characters.' });

  const genderClean = gender.trim();
  if (!['Male', 'Female'].includes(genderClean)) {
    return res.status(400).json({ error: 'Gender must be Male or Female.' });
  }

  const normalizedPhone = normalizePhone(String(telephone).trim());
  if (!normalizedPhone) {
    return res.status(400).json({
      error: 'Invalid phone number. Please enter a valid Nigerian mobile number (e.g. 08012345678).',
    });
  }

  const normalizedMembership = apc_membership_no?.trim()
    ? normalizeMembership(apc_membership_no.trim())
    : null;

  const availabilityClean = availability.trim();
  if (!['Yes', 'No'].includes(availabilityClean)) {
    return res.status(400).json({ error: 'Availability must be Yes or No.' });
  }

  if (lga          && String(lga).trim().length          > 100) return res.status(400).json({ error: 'LGA must not exceed 100 characters.' });
  if (town         && String(town).trim().length         > 100) return res.status(400).json({ error: 'Town must not exceed 100 characters.' });
  if (occupation   && String(occupation).trim().length   > 100) return res.status(400).json({ error: 'Occupation must not exceed 100 characters.' });
  if (voters_card_no && String(voters_card_no).trim().length > 50) return res.status(400).json({ error: "Voter's Card Number must not exceed 50 characters." });

  const dupChecks = [
    { field: 'telephone', value: normalizedPhone, label: 'phone number' },
  ];
  if (normalizedMembership) {
    dupChecks.push({ field: 'apc_membership_no', value: normalizedMembership, label: 'APC Membership Number' });
  }
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
      console.warn(`[REG:${requestId}] Duplicate ${check.field}: ${check.value}`);
      return res.status(409).json({
        error: `This ${check.label} is already registered.`,
        field: check.field,
      });
    }
  }

  supabase.from('reg_attempts').insert({
    ip_address:   ip,
    phone:        normalizedPhone,
    request_id:   requestId,
    attempted_at: new Date().toISOString(),
  }).then(({ error: e }) => {
    if (e) console.error(`[REG:${requestId}] Audit insert failed:`, e.message);
  });

  const { data: reg_code, error: codeError } = await supabase.rpc('get_next_reg_code');
  if (codeError || !reg_code) {
    console.error(`[REG:${requestId}] Code gen failed:`, codeError?.message);
    return res.status(500).json({ error: isProd ? 'Server error.' : codeError?.message });
  }

  const { error: insertError } = await supabase.from('registrations').insert({
    reg_code,
    surname:          surnameClean,
    other_names:      otherNamesClean,
    gender:           genderClean,
    telephone:        normalizedPhone,
    apc_membership_no: normalizedMembership,
    availability:     availabilityClean,
    lga:              lga?.trim()           || null,
    town:             town?.trim()          || null,
    occupation:       occupation?.trim()    || null,
    voters_card_no:   voters_card_no?.trim() || null,
    ip_address:       ip,
    request_id:       requestId,
  });

  if (insertError) {
    if (insertError.code === '23505') {
      const detail   = insertError.message || '';
      let dupField   = 'phone number';
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

// ── Static frontend ───────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../public')));

// ── SPA fallback ──────────────────────────────────────────────────────────────
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error(`[ERROR] ${req.method} ${req.path}:`, err.message);
  res.status(500).json({ error: 'Internal server error.' });
});

// ── Local dev server ──────────────────────────────────────────────────────────
if (!isProd) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`\n✅ production server is live at http://localhost:${PORT}\n`));
}

module.exports = app;