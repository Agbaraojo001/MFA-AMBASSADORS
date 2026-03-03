/**
 * server.local.js — Local development ONLY
 * ─────────────────────────────────────────
 * NOT deployed to Vercel. Vercel calls api/index.js directly.
 *
 * Usage:
 *   npm run dev    ← nodemon (auto-restart on file changes)
 *   npm start      ← plain node
 */
'use strict';
require('dotenv').config();

const missing = ['SUPABASE_URL','SUPABASE_SERVICE_KEY'].filter(k => !process.env[k]);
if (missing.length) {
  console.error('\n  Missing env vars:', missing.join(', '));
  console.error('  Copy .env.example → .env and fill in your Supabase credentials.\n');
  process.exit(1);
}

const app  = require('./api/index');
const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
  console.log(`\n  MFA Registration (local) → http://localhost:${PORT}`);
  console.log(`  Health check            → http://localhost:${PORT}/api/health\n`);
});

process.on('SIGINT', () => { server.close(() => process.exit(0)); });
