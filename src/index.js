import { Hono } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';

const app = new Hono();
const COOKIE = 'ld_session';
const SESSION_HOURS = 12;
const STATUSES = ['present', 'late', 'absent', 'half_day', 'wfh', 'leave', 'weekoff'];
const ROLES = ['employee', 'manager', 'admin'];

/* ───────── crypto helpers ───────── */
const enc = new TextEncoder();
const b64 = (u8) => btoa(String.fromCharCode(...u8));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');

async function hashPassword(pw, salt = crypto.getRandomValues(new Uint8Array(16)), iter = 100000) {
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, key, 256);
  return `pbkdf2$${iter}$${b64(salt)}$${b64(new Uint8Array(bits))}`;
}
async function verifyPassword(pw, stored) {
  const [, iter, salt] = stored.split('$');
  const again = await hashPassword(pw, unb64(salt), +iter);
  if (again.length !== stored.length) return false;
  let diff = 0;
  for (let i = 0; i < again.length; i++) diff |= again.charCodeAt(i) ^ stored.charCodeAt(i);
  return diff === 0;
}
async function sha256Hex(s) {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s))));
}

/* ───────── small utils ───────── */
const todayUTC = () => new Date().toISOString().slice(0, 10);
const nowSql = () => new Date().toISOString().replace('T', ' ').slice(0, 19);
function validDate(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + 'T00:00:00Z');
  return !isNaN(d) && d.toISOString().slice(0, 10) === s;
}
const validTime = (s) => /^([01]\d|2[0-3]):[0-5]\d$/.test(s);
const str = (v, max = 200) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
function workdays(from, to, half, hol) {
  let n = 0;
  for (let d = new Date(from + 'T00:00:00Z'), end = new Date(to + 'T00:00:00Z'); d <= end; d.setUTCDate(d.getUTCDate() + 1)) {
    const dow = d.getUTCDay();
    if (dow === 0 || dow === 6 || hol.has(d.toISOString().slice(0, 10))) continue;
    n++;
  }
  return half ? n * 0.5 : n;
}
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const bad = (m) => new HttpError(400, m);

/* ───────── data access ───────── */
const EMP_SQL = `SELECT e.id, e.emp_code, e.name, e.email, e.designation, e.role, e.roles, e.is_active, e.biometric_code,
  e.team_id, t.name AS team, e.manager_id, m.emp_code AS mgr, e.phone, e.must_change_password
  FROM employees e LEFT JOIN teams t ON t.id = e.team_id LEFT JOIN employees m ON m.id = e.manager_id`;
// Leave balances / allowances are not tracked for now. Flip to true to enforce them again.
const ACCOUNTING = false;
const ROLE_ORDER = ['admin', 'manager', 'employee'];
const rolesOf = (r) => String((r && (r.roles || r.role)) || 'employee').split(',').map((x) => x.trim()).filter(Boolean);
const hasRole = (r, x) => rolesOf(r).includes(x);
const primaryRole = (roles) => ROLE_ORDER.find((x) => roles.includes(x)) || 'employee';
const quotaRoleOf = (r) => (hasRole(r, 'manager') ? 'manager' : 'employee');   // which allowance column applies
const empShape = (r) => ({
  id: r.emp_code, name: r.name, email: r.email, desig: r.designation || '', role: r.role, roles: rolesOf(r), bio: r.biometric_code || '',
  team: r.team || '', mgr: r.mgr || null, active: !!r.is_active, phone: r.phone || '',
});
async function allEmployees(db) { return (await db.prepare(EMP_SQL + ' ORDER BY e.id').all()).results; }
async function empByCode(db, code) { return db.prepare(EMP_SQL + ' WHERE e.emp_code = ?').bind(code).first(); }
async function holidaySet(db) {
  return new Set((await db.prepare('SELECT date FROM holidays').all()).results.map((r) => r.date));
}
function descendantsOf(rows, id) {
  const out = new Set();
  const walk = (x) => rows.filter((e) => e.manager_id === x).forEach((e) => { if (!out.has(e.id)) { out.add(e.id); walk(e.id); } });
  walk(id);
  return out;
}
function logStmt(db, actorId, action, details) {
  return db.prepare('INSERT INTO audit_log (actor_id, action, details) VALUES (?, ?, ?)').bind(actorId, action, details);
}
async function quotaFor(db, role, type) {
  const r = role === 'employee' ? 'employee' : 'manager';
  return db.prepare(
    `SELECT lt.is_active, COALESCE(q.quota, 0) AS quota FROM leave_types lt
     LEFT JOIN leave_quotas q ON q.leave_type = lt.code AND q.role = ? WHERE lt.code = ?`).bind(r, type).first();
}
async function usedAndPending(db, empId, type, year) {
  const r = await db.prepare(
    `SELECT COALESCE(SUM(CASE WHEN status='Approved' AND start_date LIKE ? THEN days END),0) AS used,
            COALESCE(SUM(CASE WHEN status='Pending' AND start_date LIKE ? THEN days END),0) AS pend
     FROM requests WHERE employee_id = ? AND kind='leave' AND leave_type = ?`).bind(year + '%', year + '%', empId, type).first();
  return r;
}

/* ───────── middleware ───────── */
app.use('/api/*', async (c, next) => {
  if (c.req.method !== 'GET' && c.req.method !== 'HEAD') {
    const ct = c.req.header('content-type') || '';
    if (!ct.includes('application/json')) return c.json({ error: 'JSON required' }, 415);
  }
  c.header('Cache-Control', 'no-store');
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('Referrer-Policy', 'same-origin');
  await next();
});
app.onError((err, c) => {
  if (err instanceof HttpError) return c.json({ error: err.message }, err.status);
  if (err instanceof SyntaxError) return c.json({ error: 'That request was not valid.' }, 400);
  console.error(err);
  return c.json({ error: 'Something went wrong. Please try again.' }, 500);
});
app.notFound((c) => c.json({ error: 'Not found' }, 404));

async function loadUser(c) {
  const token = getCookie(c, COOKIE);
  if (!token) return null;
  const row = await c.env.DB.prepare(
    `SELECT e.id, e.emp_code, e.name, e.email, e.role, e.roles, e.is_active, e.must_change_password, s.expires_at
     FROM sessions s JOIN employees e ON e.id = s.employee_id WHERE s.token_hash = ?`).bind(await sha256Hex(token)).first();
  if (!row || !row.is_active || row.expires_at < nowSql()) return null;
  return row;
}
const requireUser = async (c, next) => {
  const u = await loadUser(c);
  if (!u) return c.json({ error: 'Please sign in.' }, 401);
  if (u.must_change_password) {
    const p = new URL(c.req.url).pathname;
    if (!(p === '/api/state' || p.startsWith('/api/auth/')))
      return c.json({ error: 'Please set a new password before continuing.', code: 'MUST_CHANGE' }, 403);
  }
  c.set('user', u);
  await next();
};
const requireRole = (...roles) => async (c, next) => {
  if (!roles.some((r) => hasRole(c.get('user'), r))) return c.json({ error: 'You do not have access to this.' }, 403);
  await next();
};
async function startSession(c, empId) {
  const raw = hex(crypto.getRandomValues(new Uint8Array(32)));
  const exp = new Date(Date.now() + SESSION_HOURS * 3600e3).toISOString().replace('T', ' ').slice(0, 19);
  await c.env.DB.batch([
    c.env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(nowSql()),
    c.env.DB.prepare('INSERT INTO sessions (token_hash, employee_id, expires_at) VALUES (?, ?, ?)').bind(await sha256Hex(raw), empId, exp),
  ]);
  setCookie(c, COOKIE, raw, {
    httpOnly: true, secure: new URL(c.req.url).protocol === 'https:', sameSite: 'Lax', path: '/', maxAge: SESSION_HOURS * 3600,
  });
}

/* ───────── auth ───────── */
// Mail can go out through the sender's own Gmail account (SMTP_USER + SMTP_PASS, an app password)
// or through Resend (RESEND_API_KEY + MAIL_FROM). Gmail needs no DNS records.
const smtpEnabled = (env) => !!(env.SMTP_USER && env.SMTP_PASS);
const emailEnabled = (env) => smtpEnabled(env) || !!(env.RESEND_API_KEY && env.MAIL_FROM);
app.get('/api/auth/status', async (c) => {
  const n = await c.env.DB.prepare('SELECT COUNT(*) AS n FROM employees').first();
  return c.json({ needsSetup: n.n === 0, emailEnabled: emailEnabled(c.env) });
});

/* ───────── forgot / reset password ───────── */
function tempPassword() {
  const a = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return [...crypto.getRandomValues(new Uint32Array(14))].map((x) => a[x % a.length]).join('');
}
async function sendResetEmail(env, to, name, link) {
  const subject = 'Reset your LeaveDesk password';
  const safeName = name.replace(/[<>&]/g, '');
  const text = `Hi ${name},\n\nUse this link to choose a new password (valid for 30 minutes):\n${link}\n\nIf you didn't ask for this, you can ignore this email and your password will stay the same.`;
  const html = `<p>Hi ${safeName},</p><p><a href="${link}">Choose a new password</a> (valid for 30 minutes).</p><p>If you didn't ask for this, you can ignore this email and your password will stay the same.</p>`;
  if (smtpEnabled(env)) {
    try {
      const { WorkerMailer } = await import('worker-mailer');
      await WorkerMailer.send(
        {
          host: env.SMTP_HOST || 'smtp.gmail.com', port: 465, secure: true, authType: 'plain',
          credentials: { username: env.SMTP_USER, password: env.SMTP_PASS },
          socketTimeoutMs: 15000, responseTimeoutMs: 15000,
        },
        { from: { name: 'LeaveDesk', email: env.SMTP_USER }, to, subject, text, html },
      );
      return { ok: true };
    } catch (e) {
      const msg = String((e && e.message) || e).split(env.SMTP_PASS).join('***').slice(0, 180);
      return { ok: false, detail: `smtp: ${msg}` };
    }
  }
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'content-type': 'application/json' },
      body: JSON.stringify({ from: env.MAIL_FROM, to: [to], subject, text, html }),
    });
    if (res.ok) return { ok: true };
    return { ok: false, detail: `${res.status} ${(await res.text()).slice(0, 180)}` };
  } catch (e) { return { ok: false, detail: 'network error' }; }
}
const NOT_ADMIN_MSG = 'You are not an administrator. Please contact your administrator to change your password.';
app.post('/api/auth/forgot', async (c) => {
  const db = c.env.DB, b = await c.req.json();
  const email = str(b.email, 200).toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw bad('Enter a valid email address.');
  const emp = await db.prepare('SELECT id, name, email, roles, role, is_active FROM employees WHERE email = ?').bind(email).first();
  // only administrators reset by email; everyone else (and unknown addresses) is told to contact their administrator
  if (!emp || !emp.is_active || !hasRole(emp, 'admin')) throw new HttpError(403, NOT_ADMIN_MSG);
  if (!emailEnabled(c.env)) throw new HttpError(503, 'Reset by email isn’t set up yet, so a link can’t be sent. Please contact the person who manages this system.');
  const recent = await db.prepare(
    `SELECT COUNT(*) AS n FROM reset_requests WHERE employee_id = ? AND created_at > datetime('now','-1 hour')`).bind(emp.id).first();
  if (recent.n >= 3) throw new HttpError(429, 'Too many reset requests. Please wait a while and check your inbox for the earlier link.');
  const token = hex(crypto.getRandomValues(new Uint8Array(32)));
  const link = `${new URL(c.req.url).origin}/?reset=${token}`;
  const sent = await sendResetEmail(c.env, emp.email, emp.name, link);
  const exp = new Date(Date.now() + 30 * 60e3).toISOString().replace('T', ' ').slice(0, 19);
  const stmts = [
    db.prepare('DELETE FROM password_resets WHERE employee_id = ? AND used_at IS NULL').bind(emp.id),
    db.prepare('INSERT INTO password_resets (employee_id, token_hash, expires_at) VALUES (?, ?, ?)').bind(emp.id, await sha256Hex(token), exp),
    db.prepare(`INSERT INTO reset_requests (employee_id, emailed, status) VALUES (?, ?, 'Open')`).bind(emp.id, sent.ok ? 1 : 0),
  ];
  if (!sent.ok) stmts.push(logStmt(db, null, 'Reset email failed', `${emp.email}: ${sent.detail}`));
  await db.batch(stmts);
  const answer = { ok: true };
  if (c.env.DEV_RETURN_RESET_TOKEN === '1') answer.devToken = token;   // local testing only
  return c.json(answer);
});
// opened from the emailed link: the person chooses their new password
app.post('/api/auth/reset', async (c) => {
  const db = c.env.DB, b = await c.req.json();
  const token = str(b.token, 200), password = String(b.password || '');
  if (password.length < 8) throw bad('Password must be at least 8 characters.');
  const row = await db.prepare(
    `SELECT id, employee_id FROM password_resets WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`
  ).bind(await sha256Hex(token), nowSql()).first();
  if (!row) throw bad('This link is invalid or has expired. Please use Forgot password to get a new one.');
  await db.batch([
    db.prepare('UPDATE employees SET password_hash = ?, must_change_password = 0 WHERE id = ?').bind(await hashPassword(password), row.employee_id),
    db.prepare('UPDATE password_resets SET used_at = ? WHERE id = ?').bind(nowSql(), row.id),
    db.prepare('DELETE FROM sessions WHERE employee_id = ?').bind(row.employee_id),
    db.prepare(`UPDATE reset_requests SET status = 'Done', handled_at = ? WHERE employee_id = ? AND status = 'Open'`).bind(nowSql(), row.employee_id),
    logStmt(db, row.employee_id, 'Password reset by email link', 'Forgot password'),
  ]);
  return c.json({ ok: true });
});

app.post('/api/auth/setup', async (c) => {
  const db = c.env.DB;
  const n = await db.prepare('SELECT COUNT(*) AS n FROM employees').first();
  if (n.n > 0) throw new HttpError(409, 'Setup is already complete.');
  const b = await c.req.json();
  const name = str(b.name, 100), email = str(b.email, 200).toLowerCase(), password = String(b.password || '');
  if (!name) throw bad('Name is required.');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw bad('Enter a valid email address.');
  if (password.length < 8) throw bad('Password must be at least 8 characters.');
  const hash = await hashPassword(password);
  const r = await db.prepare(
    `INSERT INTO employees (emp_code, name, email, designation, role, roles, password_hash) VALUES ('EMP-1001', ?, ?, 'Administrator', 'admin', 'admin,manager,employee', ?)`
  ).bind(name, email, hash).run();
  await db.batch([logStmt(db, r.meta.last_row_id, 'System set up', `First admin ${name}`)]);
  await startSession(c, r.meta.last_row_id);
  return c.json({ ok: true });
});

const LOCK_MINUTES = 15;
async function recordFailure(db, keys) {
  const now = nowSql();
  const cutoff = new Date(Date.now() - LOCK_MINUTES * 60e3).toISOString().replace('T', ' ').slice(0, 19);
  const lockUntil = new Date(Date.now() + LOCK_MINUTES * 60e3).toISOString().replace('T', ' ').slice(0, 19);
  await db.batch(keys.map(([key, max]) => db.prepare(
    `INSERT INTO login_attempts (key, fails, window_start, locked_until) VALUES (?, 1, ?, NULL)
     ON CONFLICT(key) DO UPDATE SET
       fails = CASE WHEN window_start < ? THEN 1 ELSE fails + 1 END,
       locked_until = CASE WHEN (CASE WHEN window_start < ? THEN 1 ELSE fails + 1 END) >= ? THEN ? ELSE locked_until END,
       window_start = CASE WHEN window_start < ? THEN ? ELSE window_start END`
  ).bind(key, now, cutoff, cutoff, max, lockUntil, cutoff, now)));
}
app.post('/api/auth/login', async (c) => {
  const db = c.env.DB, b = await c.req.json();
  const email = str(b.email, 200).toLowerCase(), password = String(b.password || '');
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  const keys = [[`p:${email}|${ip}`, 5], [`i:${ip}`, 30], [`e:${email}`, 40]];
  const locked = await db.prepare(
    `SELECT 1 FROM login_attempts WHERE key IN (?, ?, ?) AND locked_until IS NOT NULL AND locked_until > ? LIMIT 1`
  ).bind(...keys.map((k) => k[0]), nowSql()).first();
  if (locked) throw new HttpError(429, `Too many sign-in attempts. Please wait ${LOCK_MINUTES} minutes and try again.`);
  const row = await db.prepare('SELECT id, password_hash, is_active FROM employees WHERE email = ?').bind(email).first();
  // always do the hash work so timing does not reveal whether the email exists
  const ok = row ? await verifyPassword(password, row.password_hash) : (await hashPassword(password), false);
  if (!row || !ok || !row.is_active) {
    await recordFailure(db, keys);
    throw new HttpError(401, 'Incorrect email or password.');
  }
  await db.batch([db.prepare('DELETE FROM login_attempts WHERE key IN (?, ?)').bind(keys[0][0], keys[2][0])]);
  await startSession(c, row.id);
  return c.json({ ok: true });
});

app.post('/api/auth/logout', async (c) => {
  const token = getCookie(c, COOKIE);
  if (token) await c.env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256Hex(token)).run();
  deleteCookie(c, COOKIE, { path: '/' });
  return c.json({ ok: true });
});

app.post('/api/auth/password', requireUser, async (c) => {
  const u = c.get('user'), b = await c.req.json();
  const row = await c.env.DB.prepare('SELECT password_hash FROM employees WHERE id = ?').bind(u.id).first();
  const current = String(b.current || ''), next = String(b.next || '');
  if (!(await verifyPassword(current, row.password_hash))) throw bad('Current password is incorrect.');
  if (next.length < 8) throw bad('New password must be at least 8 characters.');
  if (next === current) throw bad('Choose a password different from the current one.');
  const keep = await sha256Hex(getCookie(c, COOKIE) || '');
  await c.env.DB.batch([
    c.env.DB.prepare('UPDATE employees SET password_hash = ?, must_change_password = 0 WHERE id = ?').bind(await hashPassword(next), u.id),
    c.env.DB.prepare('DELETE FROM sessions WHERE employee_id = ? AND token_hash <> ?').bind(u.id, keep),
    logStmt(c.env.DB, u.id, 'Password changed', u.name),
  ]);
  return c.json({ ok: true });
});

function normPhone(v) {
  const raw = String(v || '').trim();
  let d = raw.replace(/\D/g, '');
  if (!raw) return '';
  if (!d) throw bad('Enter the WhatsApp number using digits only, with country code.');
  if (d.length === 10) d = '91' + d;
  if (d.length < 8 || d.length > 15) throw bad('Enter the WhatsApp number with country code, for example 919876543210.');
  return d;
}
app.post('/api/me/phone', requireUser, async (c) => {
  const u = c.get('user'), b = await c.req.json();
  const phone = normPhone(b.phone);
  await c.env.DB.prepare('UPDATE employees SET phone = ? WHERE id = ?').bind(phone || null, u.id).run();
  return c.json({ ok: true, phone });
});

/* ───────── state (role-scoped snapshot) ───────── */
function buildRequests(rows, hist) {
  const byReq = {};
  hist.forEach((h) => {
    const text = h.action === 'Submitted' ? 'Submitted' : `${h.action}${h.actor ? ' by ' + h.actor : ''}`;
    (byReq[h.request_id] ||= []).push([text, h.created_at.slice(0, 16)]);
  });
  return rows.map((r) => ({
    no: r.request_no, emp: r.emp, appr: r.appr, kind: r.kind, type: r.leave_type, from: r.start_date, to: r.end_date,
    half: !!r.is_half_day, days: r.days, reason: r.reason, status: r.status, created: r.created_at.slice(0, 16),
    rej: r.decision_reason, hist: byReq[r.id] || [],
  }));
}
app.get('/api/state', requireUser, async (c) => {
  const db = c.env.DB, u = c.get('user');
  const rows = await allEmployees(db);
  const meRow = rows.find((r) => r.id === u.id);
  const holidays = (await db.prepare('SELECT date AS d, name AS n FROM holidays ORDER BY date').all()).results;
  const ltRows = (await db.prepare('SELECT code, name, is_active FROM leave_types ORDER BY rowid').all()).results;
  const qRows = (await db.prepare('SELECT leave_type, role, quota FROM leave_quotas').all()).results;
  const leaveTypes = ltRows.map((t) => ({
    code: t.code, name: t.name, active: !!t.is_active,
    quotas: {
      employee: (qRows.find((q) => q.leave_type === t.code && q.role === 'employee') || {}).quota || 0,
      manager: (qRows.find((q) => q.leave_type === t.code && q.role === 'manager') || {}).quota || 0,
    },
  }));
  const out = { me: { ...empShape(meRow), mustChange: !!meRow.must_change_password }, leaveTypes, accounting: ACCOUNTING, teams: [], teamLeads: {}, emps: [], holidays, reqs: [], att: {}, imports: [], audit: [] };

  const REQ_SQL = `SELECT r.*, e.emp_code AS emp, a.emp_code AS appr FROM requests r
    JOIN employees e ON e.id = r.employee_id JOIN employees a ON a.id = r.approver_id`;
  let reqRows, reqWhere = '1=1', reqBinds = [];
  if (hasRole(u, 'admin')) {
    out.emps = rows.map(empShape);
    const teams = (await db.prepare('SELECT t.name, l.emp_code AS lead FROM teams t LEFT JOIN employees l ON l.id = t.lead_id ORDER BY t.name').all()).results;
    out.teams = teams.map((t) => t.name);
    teams.forEach((t) => { if (t.lead) out.teamLeads[t.name] = t.lead; });
    reqRows = (await db.prepare(REQ_SQL + ' ORDER BY r.id DESC LIMIT 2000').all()).results;
    const since = new Date(Date.now() - 120 * 864e5).toISOString().slice(0, 10);
    const att = (await db.prepare(
      `SELECT e.emp_code, a.date, a.status, a.check_in, a.check_out, a.import_id FROM attendance a
       JOIN employees e ON e.id = a.employee_id WHERE a.date >= ?`).bind(since).all()).results;
    att.forEach((a) => { out.att[a.emp_code + '|' + a.date] = { s: a.status, in: a.check_in || '', out: a.check_out || '', batch: 'IMP-' + String(a.import_id || 0).padStart(4, '0') }; });
    out.imports = (await db.prepare(
      `SELECT i.id, i.file_name, i.uploaded_at, i.total_rows, i.valid_rows, i.error_rows, i.overwritten, u.name AS by,
         (SELECT COUNT(*) FROM attendance a WHERE a.import_id = i.id) AS owned,
         (SELECT COUNT(DISTINCT a.employee_id) FROM attendance a WHERE a.import_id = i.id) AS people
       FROM attendance_imports i JOIN employees u ON u.id = i.uploaded_by ORDER BY i.id DESC LIMIT 50`).all()).results
      .map((i) => ({ id: 'IMP-' + String(i.id).padStart(4, '0'), file: i.file_name, by: i.by, at: i.uploaded_at.slice(0, 16), total: i.total_rows, valid: i.valid_rows, errors: i.error_rows, overwritten: i.overwritten, owned: i.owned, people: i.people }));
    out.audit = (await db.prepare(
      `SELECT l.action, l.details, l.created_at FROM audit_log l ORDER BY l.id DESC LIMIT 200`).all()).results
      .map((l) => ({ a: l.action, d: l.details || '', t: l.created_at.slice(0, 16) }));
  } else {
    const directs = rows.filter((r) => r.manager_id === u.id);
    const keep = new Map();
    [meRow, ...directs].forEach((r) => keep.set(r.id, r));
    if (meRow.manager_id) { const m = rows.find((r) => r.id === meRow.manager_id); if (m) keep.set(m.id, m); }
    out.emps = [...keep.values()].map(empShape);
    reqWhere = `(r.employee_id = ? OR r.approver_id = ?
      OR r.employee_id IN (SELECT id FROM employees WHERE manager_id = ?)
      OR r.employee_id = (SELECT manager_id FROM employees WHERE id = ?))`;
    reqBinds = [u.id, u.id, u.id, u.id];
    reqRows = (await db.prepare(
      REQ_SQL + ` WHERE ${reqWhere} ORDER BY r.id DESC LIMIT 1000`).bind(...reqBinds).all()).results;
    if (u.role !== 'manager' || true) {
      const att = (await db.prepare('SELECT date, status, check_in, check_out, import_id FROM attendance WHERE employee_id = ? ORDER BY date DESC LIMIT 400').bind(u.id).all()).results;
      att.forEach((a) => { out.att[u.emp_code + '|' + a.date] = { s: a.status, in: a.check_in || '', out: a.check_out || '', batch: 'IMP-' + String(a.import_id || 0).padStart(4, '0') }; });
    }
    // a manager also sees the attendance of the people who report to them (for the attendance summary)
    if (hasRole(u, 'manager') && directs.length) {
      const since = new Date(Date.now() - 120 * 864e5).toISOString().slice(0, 10);
      const team = (await db.prepare(
        `SELECT e.emp_code, a.date, a.status, a.check_in, a.check_out, a.import_id FROM attendance a
         JOIN employees e ON e.id = a.employee_id WHERE e.manager_id = ? AND a.date >= ?`).bind(u.id, since).all()).results;
      team.forEach((a) => { out.att[a.emp_code + '|' + a.date] = { s: a.status, in: a.check_in || '', out: a.check_out || '', batch: 'IMP-' + String(a.import_id || 0).padStart(4, '0') }; });
    }
  }
  let hist = [];
  if (reqRows.length) {
    hist = (await db.prepare(
      `SELECT h.request_id, h.action, h.created_at, x.name AS actor FROM request_history h
       JOIN requests r ON r.id = h.request_id
       LEFT JOIN employees x ON x.id = h.actor_id
       WHERE h.request_id IN (SELECT r.id FROM requests r WHERE ${reqWhere} ORDER BY r.id DESC LIMIT ${hasRole(u, 'admin') ? 2000 : 1000})
       ORDER BY h.id`).bind(...reqBinds).all()).results;
  }
  out.reqs = buildRequests(reqRows, hist);
  return c.json(out);
});

/* ───────── requests (employee + manager) ───────── */
app.post('/api/requests', requireUser, async (c) => {
  const db = c.env.DB, u = c.get('user'), b = await c.req.json();
  const kind = b.kind === 'wfh' ? 'wfh' : b.kind === 'leave' ? 'leave' : null;
  if (!kind) throw bad('Invalid request type.');
  const me = await db.prepare('SELECT manager_id FROM employees WHERE id = ?').bind(u.id).first();
  if (!me.manager_id) throw bad('No reporting manager is assigned to you. Ask HR.');
  const mgr = await db.prepare('SELECT id, is_active FROM employees WHERE id = ?').bind(me.manager_id).first();
  if (!mgr || !mgr.is_active) throw bad('Your reporting manager is inactive. Ask HR.');
  const from = b.from, to = kind === 'wfh' ? b.from : b.to, half = kind === 'leave' && !!b.half;
  if (!validDate(from) || !validDate(to)) throw bad('Please select valid date(s).');
  if (to < from) throw bad('End date cannot be before start date.');
  const yesterday = new Date(Date.now() - 864e5).toISOString().slice(0, 10);
  if (from < yesterday) throw bad('You can’t apply for past dates.');
  if ((new Date(to) - new Date(from)) / 864e5 > 120) throw bad('That date range is too long.');
  const reason = str(b.reason, 500);
  if (!reason) throw bad('Please add a reason.');
  let type = null;
  if (kind === 'leave') {
    type = str(b.type, 20);
    const q = await quotaFor(db, quotaRoleOf(u), type);
    if (!q || !q.is_active) throw bad('Choose a leave type.');
    if (ACCOUNTING && !(q.quota > 0)) throw bad('That leave type is not available to you.');
  }
  const days = workdays(from, to, half, await holidaySet(db));
  if (days === 0) throw bad('Selected dates fall on weekends or holidays. Nothing to apply for.');
  const dup = await db.prepare(
    `SELECT request_no, status FROM requests WHERE employee_id = ? AND status IN ('Pending','Approved')
     AND start_date <= ? AND end_date >= ? LIMIT 1`).bind(u.id, to, from).first();
  if (dup) throw bad(`This overlaps with your ${dup.status.toLowerCase()} request ${dup.request_no}.`);
  if (ACCOUNTING && kind === 'leave') {
    const q = await quotaFor(db, quotaRoleOf(u), type);
    const bal = await usedAndPending(db, u.id, type, from.slice(0, 4));
    const rem = q.quota - bal.used - bal.pend;
    if (days > rem) throw bad(`Only ${rem} ${type} day(s) available.`);
  }
  const ins = await db.prepare(
    `INSERT INTO requests (request_no, kind, employee_id, approver_id, leave_type, start_date, end_date, is_half_day, days, reason)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(crypto.randomUUID(), kind, u.id, mgr.id, type, from, to, half ? 1 : 0, days, reason).run();
  const id = ins.meta.last_row_id;
  const no = `${kind === 'wfh' ? 'WFH' : 'LV'}-${from.slice(0, 4)}-${String(id).padStart(4, '0')}`;
  await db.batch([
    db.prepare('UPDATE requests SET request_no = ? WHERE id = ?').bind(no, id),
    db.prepare('INSERT INTO request_history (request_id, action, actor_id) VALUES (?, ?, ?)').bind(id, 'Submitted', u.id),
    db.prepare('INSERT INTO notifications (employee_id, request_id, message) VALUES (?, ?, ?)')
      .bind(mgr.id, id, `${u.name} requested ${kind === 'wfh' ? 'work from home' : type + ' leave'} (${from}${to !== from ? ' – ' + to : ''}).`),
  ]);
  return c.json({ ok: true, no, days });
});

async function loadRequest(db, no) {
  const r = await db.prepare('SELECT * FROM requests WHERE request_no = ?').bind(no).first();
  if (!r) throw new HttpError(404, 'Request not found.');
  return r;
}

app.post('/api/requests/:no/cancel', requireUser, async (c) => {
  const db = c.env.DB, u = c.get('user');
  const r = await loadRequest(db, c.req.param('no'));
  if (r.employee_id !== u.id) throw new HttpError(403, 'You can only cancel your own requests.');
  const upd = await db.prepare(`UPDATE requests SET status = 'Cancelled' WHERE id = ? AND status = 'Pending'`).bind(r.id).run();
  if (!upd.meta.changes) throw new HttpError(409, `Request is already ${r.status.toLowerCase()}.`);
  await db.batch([
    db.prepare('INSERT INTO request_history (request_id, action, actor_id) VALUES (?, ?, ?)').bind(r.id, 'Cancelled', u.id),
  ]);
  return c.json({ ok: true });
});

async function decide(c, status, reason) {
  const db = c.env.DB, u = c.get('user');
  const r = await loadRequest(db, c.req.param('no'));
  if (r.approver_id !== u.id) throw new HttpError(403, 'You are not the approver for this request.');
  if (r.status !== 'Pending') throw new HttpError(409, `Request is already ${r.status.toLowerCase()}.`);
  if (ACCOUNTING && status === 'Approved' && r.kind === 'leave') {
    const who = await db.prepare('SELECT role, roles FROM employees WHERE id = ?').bind(r.employee_id).first();
    const q = await quotaFor(db, quotaRoleOf(who), r.leave_type);
    const bal = await usedAndPending(db, r.employee_id, r.leave_type, r.start_date.slice(0, 4));
    // pending includes this request itself, so compare used + this request against quota
    if (bal.used + r.days > q.quota) throw bad('The employee does not have enough balance for this request.');
  }
  const upd = await db.prepare(
    `UPDATE requests SET status = ?, decision_reason = ?, decided_by = ?, decided_at = ? WHERE id = ? AND status = 'Pending' AND approver_id = ?`
  ).bind(status, reason, u.id, nowSql(), r.id, u.id).run();
  if (!upd.meta.changes) throw new HttpError(409, 'This request was already decided.');
  await db.batch([
    db.prepare('INSERT INTO request_history (request_id, action, actor_id) VALUES (?, ?, ?)').bind(r.id, status, u.id),
    db.prepare('INSERT INTO notifications (employee_id, request_id, message) VALUES (?, ?, ?)')
      .bind(r.employee_id, r.id, `Your request ${r.request_no} was ${status.toLowerCase()} by ${u.name}.${reason ? ' Reason: ' + reason : ''}`),
  ]);
  return c.json({ ok: true });
}
app.post('/api/requests/:no/approve', requireUser, requireRole('manager'), (c) => decide(c, 'Approved', null));
app.post('/api/requests/:no/reject', requireUser, requireRole('manager'), async (c) => {
  const b = await c.req.json();
  const reason = str(b.reason, 300);
  if (!reason) throw bad('A reason is required to reject.');
  return decide(c, 'Rejected', reason);
});

/* ───────── admin: employees ───────── */
const admin = [requireUser, requireRole('admin')];

async function resolveTeamId(db, name) {
  if (!name) return null;
  const t = await db.prepare('SELECT id FROM teams WHERE name = ?').bind(name).first();
  if (!t) throw bad(`Team “${name}” does not exist.`);
  return t.id;
}
async function validateEmployee(db, b, selfId) {
  const name = str(b.name, 100), email = str(b.email, 200).toLowerCase();
  const desig = str(b.desig, 100);
  const given = Array.isArray(b.roles) ? b.roles : (b.role ? [b.role] : []);
  const roles = ROLE_ORDER.filter((x) => given.includes(x));
  if (!roles.length) throw bad('Choose at least one role.');
  const role = primaryRole(roles);
  if (!name) throw bad('Name is required.');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw bad('Enter a valid email address.');
  const dupe = await db.prepare('SELECT id FROM employees WHERE email = ? AND id <> ?').bind(email, selfId || 0).first();
  if (dupe) throw bad('That email is already used by another employee.');
  const teamId = await resolveTeamId(db, str(b.team, 100));
  let managerId = null;
  if (b.mgr) {
    const m = await empByCode(db, str(b.mgr, 20));
    if (!m || !m.is_active || !hasRole(m, 'manager')) throw bad('Choose an active person with the Manager role as reporting manager.');
    if (selfId) {
      if (m.id === selfId) throw bad('A person can’t report to themselves.');
      if (descendantsOf(await allEmployees(db), selfId).has(m.id)) throw bad('That would create a circular reporting line.');
    }
    managerId = m.id;
  }
  if (!roles.includes('admin') && !managerId) throw bad('Everyone except administrators needs a reporting manager.');
  const phone = 'phone' in b ? normPhone(b.phone) : undefined;
  return { name, email, role, roles, desig, teamId, managerId, phone, active: b.active === false ? 0 : 1 };
}

app.post('/api/employees', ...admin, async (c) => {
  const db = c.env.DB, u = c.get('user'), b = await c.req.json();
  const v = await validateEmployee(db, b, null);
  const password = String(b.password || '');
  if (password.length < 8) throw bad('Set a temporary password of at least 8 characters.');
  let code = str(b.id, 20).toUpperCase();
  if (!code) {
    const last = await db.prepare(`SELECT MAX(CAST(SUBSTR(emp_code, 5) AS INTEGER)) AS n FROM employees`).first();
    code = 'EMP-' + ((last.n || 1000) + 1);
  }
  if (!/^EMP-\d+$/.test(code)) throw bad('Employee ID must look like EMP-1234.');
  if (await empByCode(db, code)) throw bad('That employee ID already exists.');
  await db.batch([
    db.prepare(`INSERT INTO employees (emp_code, name, email, designation, team_id, manager_id, role, roles, password_hash, is_active, phone, must_change_password)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`).bind(code, v.name, v.email, v.desig, v.teamId, v.managerId, v.role, v.roles.join(','), await hashPassword(password), v.active, v.phone || null),
    logStmt(db, u.id, 'Employee added', `${v.name} (${code}) · ${v.roles.join(', ')}`),
  ]);
  return c.json({ ok: true, id: code });
});

app.put('/api/employees/:code', ...admin, async (c) => {
  const db = c.env.DB, u = c.get('user'), b = await c.req.json();
  const cur = await empByCode(db, c.req.param('code'));
  if (!cur) throw new HttpError(404, 'Employee not found.');
  const v = await validateEmployee(db, b, cur.id);
  if (cur.id === u.id && (!v.roles.includes('admin') || !v.active)) throw bad('You can’t remove your own admin access or deactivate yourself.');
  const stmts = [
    db.prepare(`UPDATE employees SET name=?, email=?, designation=?, team_id=?, manager_id=?, role=?, roles=?, is_active=?, phone=? WHERE id=?`)
      .bind(v.name, v.email, v.desig, v.teamId, v.managerId, v.role, v.roles.join(','), v.active, v.phone === undefined ? cur.phone : (v.phone || null), cur.id),
    logStmt(db, u.id, 'Employee updated', `${v.name} (${cur.emp_code})`),
  ];
  const pw = String(b.password || '');
  if (pw && cur.id === u.id) throw bad('To change your own password, use Change password on your Profile.');
  if (pw) {
    if (pw.length < 8) throw bad('Password must be at least 8 characters.');
    stmts.push(db.prepare('UPDATE employees SET password_hash = ?, must_change_password = 1 WHERE id = ?').bind(await hashPassword(pw), cur.id));
  }
  if (!v.active || pw) stmts.push(db.prepare('DELETE FROM sessions WHERE employee_id = ?').bind(cur.id));
  if ((!v.active || !v.roles.includes('manager')) && hasRole(cur, 'manager')) {
    // they can no longer approve: hand their pending approvals to their own manager, or else another admin
    const fallback = await db.prepare(`SELECT id FROM employees WHERE role = 'admin' AND is_active = 1 AND id <> ? ORDER BY id LIMIT 1`).bind(cur.id).first();
    const newApprover = v.managerId || (fallback && fallback.id) || null;
    if (newApprover) {
      stmts.push(db.prepare(`UPDATE requests SET approver_id = ? WHERE approver_id = ? AND status = 'Pending' AND employee_id <> ?`).bind(newApprover, cur.id, newApprover));
      stmts.push(logStmt(db, u.id, 'Pending approvals reassigned', `${cur.name}'s pending requests moved to another approver`));
    }
  }
  // a team lead who leaves their team (or is deactivated) is no longer lead
  stmts.push(db.prepare('UPDATE teams SET lead_id = NULL WHERE lead_id = ? AND (id <> COALESCE(?, -1) OR ? = 0)').bind(cur.id, v.teamId, v.active));
  await db.batch(stmts);
  return c.json({ ok: true });
});

app.post('/api/employees/bulk', ...admin, async (c) => {
  const db = c.env.DB, u = c.get('user'), b = await c.req.json();
  const ids = Array.isArray(b.ids) ? b.ids.map((x) => str(x, 20)) : [];
  if (!ids.length) throw bad('Select at least one person.');
  const all = await allEmployees(db);
  const byCode = new Map(all.map((e) => [e.emp_code, e]));
  let teamId;
  if ('team' in b) teamId = await resolveTeamId(db, str(b.team, 100));
  let mgr = null;
  if ('mgr' in b) {
    mgr = byCode.get(str(b.mgr, 20));
    if (!mgr || !mgr.is_active || !hasRole(mgr, 'manager')) throw bad('Choose an active person with the Manager role.');
  }
  const stmts = [], skipped = [], moved = [];
  for (const code of [...new Set(ids)]) {
    const e = byCode.get(code);
    if (!e) continue;
    if ('mgr' in b && (e.id === mgr.id || descendantsOf(all, e.id).has(mgr.id))) { skipped.push(e.name); continue; }
    if ('team' in b) {
      stmts.push(db.prepare('UPDATE employees SET team_id = ? WHERE id = ?').bind(teamId, e.id));
      stmts.push(db.prepare('UPDATE teams SET lead_id = NULL WHERE lead_id = ? AND id <> COALESCE(?, -1)').bind(e.id, teamId));
    }
    if ('mgr' in b) stmts.push(db.prepare('UPDATE employees SET manager_id = ? WHERE id = ?').bind(mgr.id, e.id));
    moved.push(e.name);
  }
  if (moved.length) {
    stmts.push(logStmt(db, u.id, 'Bulk update',
      `${moved.slice(0, 20).join(', ')}${moved.length > 20 ? ` and ${moved.length - 20} more` : ''}${'team' in b ? ' → team ' + (b.team || 'none') : ''}${'mgr' in b ? ' → manager ' + mgr.name : ''}`));
    for (let i = 0; i < stmts.length; i += 80) await db.batch(stmts.slice(i, i + 80));   // D1 allows at most 100 statements per batch
  }
  return c.json({ ok: true, updated: moved.length, skipped });
});

/* ───────── admin: teams ───────── */
app.post('/api/teams', ...admin, async (c) => {
  const db = c.env.DB, u = c.get('user'), name = str((await c.req.json()).name, 100);
  if (!name) throw bad('Team name is required.');
  if (await db.prepare('SELECT 1 FROM teams WHERE LOWER(name) = LOWER(?)').bind(name).first()) throw bad('A team with this name already exists.');
  await db.batch([db.prepare('INSERT INTO teams (name) VALUES (?)').bind(name), logStmt(db, u.id, 'Team created', name)]);
  return c.json({ ok: true });
});
app.post('/api/teams/rename', ...admin, async (c) => {
  const db = c.env.DB, u = c.get('user'), b = await c.req.json();
  const old = str(b.old, 100), name = str(b.name, 100);
  if (!name) throw bad('Team name is required.');
  if (await db.prepare('SELECT 1 FROM teams WHERE LOWER(name) = LOWER(?) AND name <> ?').bind(name, old).first()) throw bad('A team with this name already exists.');
  await db.batch([db.prepare('UPDATE teams SET name = ? WHERE name = ?').bind(name, old), logStmt(db, u.id, 'Team renamed', `${old} → ${name}`)]);
  return c.json({ ok: true });
});
app.post('/api/teams/delete', ...admin, async (c) => {
  const db = c.env.DB, u = c.get('user'), name = str((await c.req.json()).name, 100);
  const t = await db.prepare('SELECT id FROM teams WHERE name = ?').bind(name).first();
  if (!t) throw new HttpError(404, 'Team not found.');
  const n = await db.prepare('SELECT COUNT(*) AS n FROM employees WHERE team_id = ?').bind(t.id).first();
  if (n.n) throw bad('Move the team’s members out before deleting it.');
  await db.batch([db.prepare('DELETE FROM teams WHERE id = ?').bind(t.id), logStmt(db, u.id, 'Team deleted', name)]);
  return c.json({ ok: true });
});
app.post('/api/teams/lead', ...admin, async (c) => {
  const db = c.env.DB, u = c.get('user'), b = await c.req.json();
  const t = await db.prepare('SELECT id FROM teams WHERE name = ?').bind(str(b.team, 100)).first();
  if (!t) throw new HttpError(404, 'Team not found.');
  let leadId = null;
  if (b.lead) {
    const e = await empByCode(db, str(b.lead, 20));
    if (!e || e.team_id !== t.id || !e.is_active) throw bad('The lead must be an active member of the team.');
    leadId = e.id;
  }
  await db.batch([db.prepare('UPDATE teams SET lead_id = ? WHERE id = ?').bind(leadId, t.id), logStmt(db, u.id, 'Team lead changed', `${b.team}: ${b.lead || 'not set'}`)]);
  return c.json({ ok: true });
});

/* ───────── admin: leave policy ───────── */
function checkDays(v, label) {
  const n = Number(v);
  if (v === '' || v === null || v === undefined || !isFinite(n) || n < 0 || n > 366 || Math.round(n * 2) !== n * 2)
    throw bad(`${label}: enter days between 0 and 366, in steps of 0.5.`);
  return n;
}
app.post('/api/leave-types', ...admin, async (c) => {
  const db = c.env.DB, u = c.get('user'), b = await c.req.json();
  const name = str(b.name, 40);
  if (!name) throw bad('Leave type name is required.');
  const emp = checkDays(b.employee, 'Employees'), mgr = checkDays(b.manager, 'Managers');
  const count = await db.prepare('SELECT COUNT(*) AS n FROM leave_types').first();
  if (count.n >= 20) throw bad('You can have at most 20 leave types.');
  if (await db.prepare('SELECT 1 FROM leave_types WHERE LOWER(name) = LOWER(?)').bind(name).first()) throw bad('A leave type with this name already exists.');
  let code = name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 30) || 'leave';
  for (let i = 2; await db.prepare('SELECT 1 FROM leave_types WHERE code = ?').bind(code).first(); i++) code = code.slice(0, 26) + '_' + i;
  await db.batch([
    db.prepare('INSERT INTO leave_types (code, name, yearly_quota, is_active) VALUES (?, ?, ?, 1)').bind(code, name, emp),
    db.prepare('INSERT INTO leave_quotas (leave_type, role, quota) VALUES (?, ?, ?)').bind(code, 'employee', emp),
    db.prepare('INSERT INTO leave_quotas (leave_type, role, quota) VALUES (?, ?, ?)').bind(code, 'manager', mgr),
    logStmt(db, u.id, 'Leave type added', `${name} · employees ${emp}, managers ${mgr} days`),
  ]);
  return c.json({ ok: true, code });
});
app.put('/api/leave-types/:code', ...admin, async (c) => {
  const db = c.env.DB, u = c.get('user'), b = await c.req.json();
  const code = c.req.param('code');
  const cur = await db.prepare('SELECT name FROM leave_types WHERE code = ?').bind(code).first();
  if (!cur) throw new HttpError(404, 'Leave type not found.');
  const name = str(b.name, 40);
  if (!name) throw bad('Leave type name is required.');
  const emp = checkDays(b.employee, 'Employees'), mgr = checkDays(b.manager, 'Managers');
  if (await db.prepare('SELECT 1 FROM leave_types WHERE LOWER(name) = LOWER(?) AND code <> ?').bind(name, code).first()) throw bad('A leave type with this name already exists.');
  const active = b.active === false ? 0 : 1;
  await db.batch([
    db.prepare('UPDATE leave_types SET name = ?, is_active = ? WHERE code = ?').bind(name, active, code),
    db.prepare(`INSERT INTO leave_quotas (leave_type, role, quota) VALUES (?, 'employee', ?)
      ON CONFLICT(leave_type, role) DO UPDATE SET quota = excluded.quota`).bind(code, emp),
    db.prepare(`INSERT INTO leave_quotas (leave_type, role, quota) VALUES (?, 'manager', ?)
      ON CONFLICT(leave_type, role) DO UPDATE SET quota = excluded.quota`).bind(code, mgr),
    logStmt(db, u.id, 'Leave policy updated', `${name} · employees ${emp}, managers ${mgr} days${active ? '' : ' · turned off'}`),
  ]);
  return c.json({ ok: true });
});

/* ───────── admin: holidays ───────── */
app.post('/api/holidays', ...admin, async (c) => {
  const db = c.env.DB, u = c.get('user'), b = await c.req.json();
  const d = b.d, n = str(b.n, 100), old = b.old || null;
  if (!validDate(d) || !n) throw bad('Date and name are required.');
  const clash = await db.prepare('SELECT name FROM holidays WHERE date = ? AND date <> ?').bind(d, old || '').first();
  if (clash) throw bad(`${d} already has a holiday: ${clash.name}.`);
  if (old) await db.batch([db.prepare('UPDATE holidays SET date = ?, name = ? WHERE date = ?').bind(d, n, old), logStmt(db, u.id, 'Holiday updated', `${n} · ${d}`)]);
  else await db.batch([db.prepare('INSERT INTO holidays (date, name) VALUES (?, ?)').bind(d, n), logStmt(db, u.id, 'Holiday added', `${n} · ${d}`)]);
  return c.json({ ok: true });
});
app.post('/api/holidays/delete', ...admin, async (c) => {
  const db = c.env.DB, u = c.get('user'), d = (await c.req.json()).d;
  const h = await db.prepare('SELECT name FROM holidays WHERE date = ?').bind(d).first();
  if (!h) throw new HttpError(404, 'Holiday not found.');
  await db.batch([db.prepare('DELETE FROM holidays WHERE date = ?').bind(d), logStmt(db, u.id, 'Holiday deleted', `${h.name} · ${d}`)]);
  return c.json({ ok: true });
});

/* ───────── admin: attendance import (server re-validates everything) ───────── */
app.post('/api/attendance/import', ...admin, async (c) => {
  const db = c.env.DB, u = c.get('user'), b = await c.req.json();
  const rows = Array.isArray(b.rows) ? b.rows.slice(0, 5000) : [];
  if (!rows.length) throw bad('The file has no rows.');
  const emps = new Map((await allEmployees(db)).map((e) => [e.emp_code, e]));
  const limit = new Date(Date.now() + 864e5).toISOString().slice(0, 10);
  const seen = new Set(), valid = [], errors = [];
  rows.forEach((r, i) => {
    const n = r.n || i + 2, code = str(r.code, 20).toUpperCase(), date = str(r.date, 10), s = str(r.s, 20).toLowerCase();
    const cin = str(r.in, 5), cout = str(r.out, 5), errs = [];
    const e = emps.get(code);
    if (!e) errs.push(`Unknown employee ${code || '(blank)'}`); else if (!e.is_active) errs.push(`${code} is inactive`);
    if (!validDate(date)) errs.push(`Invalid date “${date}”`);
    else {
      if (date > limit) errs.push('Date is in the future');
      const dw = new Date(date + 'T00:00:00Z').getUTCDay();
      if (dw === 0 || dw === 6) errs.push('Date falls on a weekend');
    }
    if (!STATUSES.includes(s)) errs.push(`Unknown status “${s}”`);
    if (cin && !validTime(cin)) errs.push(`Bad check-in “${cin}”`);
    if (cout && !validTime(cout)) errs.push(`Bad check-out “${cout}”`);
    if (validTime(cin) && validTime(cout) && cout <= cin) errs.push('Check-out is not after check-in');
    if (['present', 'late', 'half_day'].includes(s) && !cin) errs.push('Check-in required for this status');
    const key = code + '|' + date;
    if (!errs.length) { if (seen.has(key)) errs.push('Duplicate of an earlier row in this file'); seen.add(key); }
    if (errs.length) errors.push({ n, msg: errs.join('; ') });
    else valid.push({ e, date, s, cin, cout });
  });
  const exist = new Set();
  if (valid.length) {
    const dates = [...new Set(valid.map((v) => v.date))];
    for (let i = 0; i < dates.length; i += 80) {
      const part = dates.slice(i, i + 80);
      const got = (await db.prepare(`SELECT employee_id, date FROM attendance WHERE date IN (${part.map(() => '?').join(',')})`).bind(...part).all()).results;
      got.forEach((g) => exist.add(g.employee_id + '|' + g.date));
    }
  }
  const overwritten = valid.filter((v) => exist.has(v.e.id + '|' + v.date)).length;
  const imp = await db.prepare(
    'INSERT INTO attendance_imports (file_name, uploaded_by, total_rows, valid_rows, error_rows, overwritten) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(str(b.file, 200) || 'upload.csv', u.id, rows.length, valid.length, errors.length, overwritten).run();
  const importId = imp.meta.last_row_id;
  for (let i = 0; i < valid.length; i += 50) {
    await db.batch(valid.slice(i, i + 50).map((v) => db.prepare(
      `INSERT INTO attendance (employee_id, date, status, check_in, check_out, import_id) VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(employee_id, date) DO UPDATE SET status = excluded.status, check_in = excluded.check_in,
         check_out = excluded.check_out, import_id = excluded.import_id`
    ).bind(v.e.id, v.date, v.s, v.cin || null, v.cout || null, importId)));
  }
  const no = 'IMP-' + String(importId).padStart(4, '0');
  await db.batch([logStmt(db, u.id, `Attendance import ${no}`, `${str(b.file, 200)} · ${valid.length} saved, ${errors.length} skipped`)]);
  return c.json({ ok: true, id: no, total: rows.length, valid: valid.length, errors, overwritten });
});

/* ───────── admin: attendance from the biometric "Weekly Periodic Report" ───────── */
app.post('/api/attendance/report', ...admin, async (c) => {
  const db = c.env.DB, u = c.get('user'), b = await c.req.json();
  const people = Array.isArray(b.people) ? b.people.slice(0, 300) : [];
  if (!people.length) throw bad('There is nobody to import.');
  const cutoff = b.cutoff;
  if (!validDate(cutoff)) throw bad('Choose the date the records run up to.');
  if (cutoff > new Date(Date.now() + 864e5).toISOString().slice(0, 10)) throw bad('That date is in the future.');
  const emps = new Map((await allEmployees(db)).map((e) => [e.emp_code, e]));
  const OK = ['present', 'half_day', 'absent', 'weekoff'];
  const errors = [], rows = [], links = [], used = new Set();
  let afterCutoff = 0, peopleSaved = 0;
  const err = (m) => { if (errors.length < 200) errors.push(m); };
  for (const p of people) {
    const e = emps.get(str(p.emp, 20)), label = str(p.name, 80) || str(p.code, 20) || 'Someone';
    if (!e) { err(`${label}: not matched to an employee`); continue; }
    if (!e.is_active) { err(`${e.name} is inactive`); continue; }
    if (used.has(e.id)) { err(`${e.name} is matched to more than one person in the file`); continue; }
    used.add(e.id);
    let n = 0;
    for (const d of (Array.isArray(p.days) ? p.days.slice(0, 400) : [])) {
      if (!validDate(d.d)) { err(`${e.name}: bad date “${str(d.d, 12)}”`); continue; }
      if (d.d > cutoff) { afterCutoff++; continue; }
      const s = str(d.s, 12), cin = str(d.in, 5), cout = str(d.out, 5);
      if (!OK.includes(s)) { err(`${e.name} ${d.d}: unknown status “${s}”`); continue; }
      if ((cin && !validTime(cin)) || (cout && !validTime(cout))) { err(`${e.name} ${d.d}: bad time`); continue; }
      rows.push({ id: e.id, date: d.d, s, cin, cout }); n++;
    }
    if (n) { peopleSaved++; const code = str(p.code, 20); if (code) links.push([e.id, code]); }
  }
  if (!rows.length) throw bad('There are no records to import' + (errors.length ? ': ' + errors[0] : '.'));
  const dates = [...new Set(rows.map((r) => r.date))];
  const existing = new Set();
  for (let i = 0; i < dates.length; i += 80) {
    const part = dates.slice(i, i + 80);
    (await db.prepare(`SELECT employee_id, date FROM attendance WHERE date IN (${part.map(() => '?').join(',')})`).bind(...part).all())
      .results.forEach((g) => existing.add(g.employee_id + '|' + g.date));
  }
  const overwritten = rows.filter((r) => existing.has(r.id + '|' + r.date)).length;
  const imp = await db.prepare(
    'INSERT INTO attendance_imports (file_name, uploaded_by, total_rows, valid_rows, error_rows, overwritten) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(str(b.file, 200) || 'report.xls', u.id, rows.length + afterCutoff, rows.length, errors.length, overwritten).run();
  const importId = imp.meta.last_row_id;
  for (let i = 0; i < rows.length; i += 50) {
    await db.batch(rows.slice(i, i + 50).map((r) => db.prepare(
      `INSERT INTO attendance (employee_id, date, status, check_in, check_out, import_id) VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(employee_id, date) DO UPDATE SET status = excluded.status, check_in = excluded.check_in,
         check_out = excluded.check_out, import_id = excluded.import_id`
    ).bind(r.id, r.date, r.s, r.cin || null, r.cout || null, importId)));
  }
  // remember which biometric code belongs to whom, so the next upload matches by itself
  const linkStmts = [];
  for (const [empId, code] of links) {
    linkStmts.push(db.prepare('UPDATE employees SET biometric_code = NULL WHERE biometric_code = ? AND id <> ?').bind(code, empId));
    linkStmts.push(db.prepare('UPDATE employees SET biometric_code = ? WHERE id = ?').bind(code, empId));
  }
  for (let i = 0; i < linkStmts.length; i += 80) await db.batch(linkStmts.slice(i, i + 80));
  const no = 'IMP-' + String(importId).padStart(4, '0');
  await db.batch([logStmt(db, u.id, `Attendance import ${no}`, `${str(b.file, 200)} · ${rows.length} records for ${peopleSaved} people, up to ${cutoff}`)]);
  return c.json({ ok: true, id: no, people: peopleSaved, records: rows.length, afterCutoff, overwritten, errors: errors.slice(0, 20) });
});

/* ───────── admin: delete an attendance import ─────────
   Removes only the attendance records this import currently owns, then the import itself.
   Records saved by other imports, and everything else in the system, are left alone. */
app.post('/api/attendance/imports/:id/delete', ...admin, async (c) => {
  const db = c.env.DB, u = c.get('user');
  const m = /^IMP-(\d{1,9})$/.exec(c.req.param('id'));
  if (!m) throw bad('That import number is not valid.');
  const id = Number(m[1]);
  const imp = await db.prepare('SELECT id, file_name FROM attendance_imports WHERE id = ?').bind(id).first();
  if (!imp) throw new HttpError(404, 'Import not found.');
  const owned = await db.prepare('SELECT COUNT(*) AS n FROM attendance WHERE import_id = ?').bind(id).first();
  await db.batch([
    db.prepare('DELETE FROM attendance WHERE import_id = ?').bind(id),
    db.prepare('DELETE FROM attendance_imports WHERE id = ?').bind(id),
    logStmt(db, u.id, `Attendance import IMP-${String(id).padStart(4, '0')} deleted`, `${imp.file_name} · ${owned.n} attendance records removed`),
  ]);
  return c.json({ ok: true, removed: owned.n });
});

export default app;
