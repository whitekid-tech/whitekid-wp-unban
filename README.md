# WHITEKID WP BAN
WhatsApp scam safety platform. Developed and maintained by **Whitekid Tech**. Independent project, not affiliated with or endorsed by WhatsApp or Meta. No tool here can unban a number: only WhatsApp can.

## Features
Scam report generator (5 languages, email/WhatsApp send) · AI/pattern message detector · link scanner · QR image scanner · number reputation (community reports) · unban/ban guidance and emergency recovery · safety academy · live alert center · report history + PDF export (print) · light/dark theme · PWA · public reputation API · feedback/support · admin dashboard (analytics, moderation, alerts, announcement, maintenance, status).

## Setup on Render
1. Push all files to GitHub (keep them in the repo root).
2. Render → New → **Blueprint** (uses `render.yaml`, creates the web service + Postgres), or create a Postgres database and a Web Service by hand.
3. Environment variables:

| Variable | Needed | Purpose |
|---|---|---|
| `DATABASE_URL` | yes | Postgres connection string (Render fills it from the blueprint). Tables are created automatically. |
| `ADMIN_PASSWORD` | yes | Password for `/admin`. Use a long random one. |
| `SESSION_SECRET` | recommended | Signs admin sessions and hashes numbers. Keep it stable: changing it resets number matching. |
| `ANTHROPIC_API_KEY` | optional | Turns on AI explanations in the detector. Create one at console.anthropic.com. |
| `AI_MODEL` | optional | Default `claude-haiku-5-5`. |
| `GOOGLE_SAFE_BROWSING_KEY` | optional | Adds Google Safe Browsing to the link scanner. |
| `SUPPORT_EMAIL` / `SUPPORT_WA_NUMBER` | optional | Targets for the report buttons. |

4. Open `/admin` and sign in with `ADMIN_PASSWORD`.

## Privacy and anti-abuse
Phone numbers are stored only as HMAC hashes plus a masked form. Reputation counts distinct reporters, one report per person per number, daily limits per IP, and every report can be rejected by an admin. Results are always labelled unverified community reports. Public pages never list full numbers or evidence.
Note: Render's free Postgres has limits and can expire; use a paid plan for permanent data.

## Not included yet
Screenshot upload and AI evidence analysis (needs file storage such as S3/R2), live cybersecurity news feed (needs a news/RSS source), and multi-admin roles.
