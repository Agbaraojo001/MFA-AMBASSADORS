# MFA Ambassadors — Portal Gate Instructions

## How It Works

The registration portal is controlled by a **single environment variable**:

```
REGISTRATION_OPEN=true   →  Portal is live, users can register normally
REGISTRATION_OPEN=false  →  Every route shows the "portal closed" page
```

When closed, visitors on **any URL** (e.g. `/`, `/register`, `/anything`) will see the styled
**"Dear Prospective Attendee…"** message. API endpoints return a `503` JSON response.
The `/api/health` endpoint is always reachable (for uptime monitors / Vercel).

---

## Files Changed / Added

| File | What changed |
|------|-------------|
| `api/index.js` | Added gate middleware (reads `REGISTRATION_OPEN`) |
| `public/closed.html` | New styled closed-portal page |
| `.env` | Added `REGISTRATION_OPEN=false` |

---

## 🔴 To CLOSE the portal (current state)

### On Vercel (production)
1. Go to your project on **vercel.com**
2. **Settings → Environment Variables**
3. Set `REGISTRATION_OPEN` = `false`
4. Click **Save**, then **Redeploy** (or push any commit — Vercel redeploys automatically)

### Locally (for testing)
In your `.env` file:
```
REGISTRATION_OPEN=false
```
Restart the server: `node server.local.js`

---

## 🟢 To REOPEN the portal (when you're ready for more registrations)

### On Vercel (production)
1. Go to **Settings → Environment Variables**
2. Change `REGISTRATION_OPEN` = `true`
3. **Save** → **Redeploy**

That's it. No code change needed. The same codebase handles both states.

### Locally
In `.env`:
```
REGISTRATION_OPEN=true
```
Restart the server.

---

## Git Commands

### Committing these changes

```bash
git add api/index.js public/closed.html .env PORTAL-GATE-INSTRUCTIONS.md
git commit -m "feat: add registration gate — portal closed (REGISTRATION_OPEN flag)"
```

### Pushing to your branch

```bash
# If your branch already exists remotely:
git push origin <your-branch-name>

# If this is a new branch being pushed for the first time:
git push -u origin <your-branch-name>
```

Replace `<your-branch-name>` with your actual branch name (e.g. `feat/portal-gate` or `main`).

---

## Quick Reference Summary

| What you want | Action |
|---|---|
| Close portal now | Set `REGISTRATION_OPEN=false` on Vercel → Redeploy |
| Reopen portal later | Set `REGISTRATION_OPEN=true` on Vercel → Redeploy |
| Test locally (closed) | `.env` → `REGISTRATION_OPEN=false` → restart server |
| Test locally (open) | `.env` → `REGISTRATION_OPEN=true` → restart server |