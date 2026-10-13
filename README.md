# Leave Management

Responsive leave and WFH management app for employees, managers and admins.
Runs on Cloudflare Workers with a D1 (SQLite) database.

## Apps
One sign-in page (`/`). After login the role decides where you land:
- `dist/index.html` – the only login page (also first-time administrator setup)
- `dist/employee.html` → `/employee` – apply for leave/WFH, requests, holidays, attendance
- `dist/manager.html` → `/manager` – approvals, team calendar, reports
- `dist/admin.html` → `/admin` – employees, teams, holidays, attendance CSV, reports

Managers can switch to "My leave"; admins can switch to Approvals and My leave.
Opening any app page while signed out sends you to the login page and back afterwards.

## Backend
- `src/index.js` – Hono API (`/api/*`): auth, role-scoped state, requests, approvals, admin
- `migrations/0001_init.sql` – D1 schema (source of truth)
- `wrangler.jsonc` – Worker, static assets and D1 binding

## Local development
```bash
npm install
npm run migrate:local
npm run dev        # http://localhost:8787
```
Open `/admin.html` first: the first visit asks you to create the administrator account.

## Deploy
```bash
npx wrangler d1 create leave-management      # once; put the id in wrangler.jsonc
npm run migrate:remote
npm run deploy
```

## Security notes
- Passwords: PBKDF2-SHA256, 100k iterations. Sessions: random token, only its hash is stored, HttpOnly cookie.
- Every route is checked server-side by role; approvals check the request's assigned approver.
- Not yet included: login rate limiting, email delivery of notifications, password reset by email.

