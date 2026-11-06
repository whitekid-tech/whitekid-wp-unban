# Whitekid Wp Ban
Scam-report helper. Enter a scammer's number → auto-written report → send to WhatsApp support by email or WhatsApp.

## Deploy on Render
1. Push this folder to GitHub.
2. Render → New → Web Service → pick the repo.
3. Build: `npm install` — Start: `npm start`.
4. Set `ADMIN_KEY` to a long secret, then open `/admin` to manage reports.
5. Optional env vars: `SUPPORT_EMAIL` (default support@whatsapp.com), `SUPPORT_WA_NUMBER` (digits only, a WhatsApp number to send the message to; blank lets the user pick a chat).

Note: Render free tier wipes the `data/` folder on redeploy/restart, so report counters reset. Attach a disk or use a database for permanence.
