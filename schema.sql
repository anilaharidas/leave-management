-- Leave Management App – SQLite schema
PRAGMA foreign_keys = ON;

-- ───────── 1. Organization & people ─────────
CREATE TABLE teams (
  id          INTEGER PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE employees (
  id            INTEGER PRIMARY KEY,
  emp_code      TEXT NOT NULL UNIQUE,                -- e.g. EMP-1042 (used in attendance CSV)
  name          TEXT NOT NULL,
  email         TEXT NOT NULL UNIQUE,
  phone         TEXT,
  designation   TEXT,
  team_id       INTEGER REFERENCES teams(id),
  manager_id    INTEGER REFERENCES employees(id),    -- configured reporting manager
  role          TEXT NOT NULL DEFAULT 'employee' CHECK (role IN ('employee','manager','admin')),
  password_hash TEXT NOT NULL,
  joined_on     TEXT,
  is_active     INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  CHECK (manager_id IS NULL OR manager_id <> id)
);
CREATE INDEX idx_emp_manager ON employees(manager_id);
CREATE INDEX idx_emp_team    ON employees(team_id);

-- ───────── 2. Leave policy & balances ─────────
CREATE TABLE leave_types (
  id             INTEGER PRIMARY KEY,
  code           TEXT NOT NULL UNIQUE,               -- annual, sick, casual
  name           TEXT NOT NULL,
  yearly_quota   REAL NOT NULL,
  allow_half_day INTEGER NOT NULL DEFAULT 1,
  count_weekends INTEGER NOT NULL DEFAULT 0,         -- policy: are weekends counted?
  count_holidays INTEGER NOT NULL DEFAULT 0,         -- policy: are holidays counted?
  is_active      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE leave_balances (                        -- one row per employee/type/year
  id           INTEGER PRIMARY KEY,
  employee_id  INTEGER NOT NULL REFERENCES employees(id),
  leave_type_id INTEGER NOT NULL REFERENCES leave_types(id),
  year         INTEGER NOT NULL,
  allotted     REAL NOT NULL,
  used         REAL NOT NULL DEFAULT 0,              -- updated only on approval
  UNIQUE (employee_id, leave_type_id, year)
);

CREATE TABLE holidays (
  id         INTEGER PRIMARY KEY,
  date       TEXT NOT NULL UNIQUE,                   -- YYYY-MM-DD
  name       TEXT NOT NULL,
  created_by INTEGER REFERENCES employees(id)
);

-- ───────── 3. Requests (leave + WFH) ─────────
CREATE TABLE requests (
  id            INTEGER PRIMARY KEY,
  request_no    TEXT NOT NULL UNIQUE,                -- LV-2026-0187 / WFH-2026-0112
  kind          TEXT NOT NULL CHECK (kind IN ('leave','wfh')),
  employee_id   INTEGER NOT NULL REFERENCES employees(id),
  approver_id   INTEGER NOT NULL REFERENCES employees(id),  -- snapshot of manager at submit time
  leave_type_id INTEGER REFERENCES leave_types(id),  -- NULL for WFH
  start_date    TEXT NOT NULL,
  end_date      TEXT NOT NULL,
  is_half_day   INTEGER NOT NULL DEFAULT 0,
  days          REAL NOT NULL,                       -- working days counted per policy
  reason        TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending','Approved','Rejected','Cancelled')),
  decision_reason TEXT,                              -- rejection reason
  decided_by    INTEGER REFERENCES employees(id),
  decided_at    TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  CHECK (end_date >= start_date),
  CHECK ((kind = 'leave' AND leave_type_id IS NOT NULL) OR (kind = 'wfh' AND leave_type_id IS NULL)),
  CHECK (status <> 'Rejected' OR decision_reason IS NOT NULL)
);
CREATE INDEX idx_req_employee ON requests(employee_id, status);
CREATE INDEX idx_req_approver ON requests(approver_id, status);
CREATE INDEX idx_req_dates    ON requests(start_date, end_date);

CREATE TABLE request_history (                       -- timeline shown in request detail
  id         INTEGER PRIMARY KEY,
  request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  action     TEXT NOT NULL,                          -- Submitted / Approved / Rejected / Cancelled
  actor_id   INTEGER REFERENCES employees(id),
  note       TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_hist_req ON request_history(request_id);

-- Secure review links: a link only locates the request; the manager must still log in
CREATE TABLE approval_links (
  id         INTEGER PRIMARY KEY,
  request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  used_at    TEXT
);

CREATE TABLE notifications (
  id           INTEGER PRIMARY KEY,
  employee_id  INTEGER NOT NULL REFERENCES employees(id),
  request_id   INTEGER REFERENCES requests(id),
  channel      TEXT NOT NULL DEFAULT 'in_app' CHECK (channel IN ('in_app','email','sms','whatsapp')),
  message      TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','sent','failed')),
  is_read      INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_notif_emp ON notifications(employee_id, is_read);

-- ───────── 4. Attendance (separate from requests) ─────────
CREATE TABLE attendance_imports (
  id          INTEGER PRIMARY KEY,                   -- import batch ID
  file_name   TEXT NOT NULL,
  uploaded_by INTEGER NOT NULL REFERENCES employees(id),
  uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
  total_rows  INTEGER NOT NULL,
  valid_rows  INTEGER NOT NULL,
  error_rows  INTEGER NOT NULL DEFAULT 0,
  status      TEXT NOT NULL DEFAULT 'confirmed' CHECK (status IN ('previewed','confirmed','cancelled'))
);

CREATE TABLE attendance (
  id          INTEGER PRIMARY KEY,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  date        TEXT NOT NULL,
  status      TEXT NOT NULL CHECK (status IN ('present','late','absent','half_day','wfh','leave','holiday')),
  check_in    TEXT,
  check_out   TEXT,
  import_id   INTEGER REFERENCES attendance_imports(id),
  UNIQUE (employee_id, date),
  CHECK (check_out IS NULL OR check_in IS NULL OR check_out > check_in)
);
CREATE INDEX idx_att_date ON attendance(date);

CREATE TABLE attendance_import_errors (               -- row-level validation errors shown in preview
  id         INTEGER PRIMARY KEY,
  import_id  INTEGER NOT NULL REFERENCES attendance_imports(id) ON DELETE CASCADE,
  row_number INTEGER NOT NULL,
  message    TEXT NOT NULL
);

-- ───────── 5. Auth & audit ─────────
CREATE TABLE sessions (
  id          TEXT PRIMARY KEY,                      -- random session token
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  expires_at  TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE audit_log (                              -- admin changes, imports, status changes
  id          INTEGER PRIMARY KEY,
  actor_id    INTEGER REFERENCES employees(id),
  action      TEXT NOT NULL,                         -- e.g. employee.update, holiday.create, attendance.import
  entity      TEXT NOT NULL,
  entity_id   INTEGER,
  details     TEXT,                                  -- JSON: old/new values
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_audit_entity ON audit_log(entity, entity_id);
