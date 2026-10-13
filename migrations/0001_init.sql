-- Leave Management – D1 (SQLite) schema

CREATE TABLE teams (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE,
  lead_id    INTEGER REFERENCES employees(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE employees (
  id            INTEGER PRIMARY KEY,
  emp_code      TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  email         TEXT NOT NULL UNIQUE,
  designation   TEXT,
  team_id       INTEGER REFERENCES teams(id),
  manager_id    INTEGER REFERENCES employees(id),
  role          TEXT NOT NULL DEFAULT 'employee' CHECK (role IN ('employee','manager','admin')),
  password_hash TEXT NOT NULL,
  is_active     INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  CHECK (manager_id IS NULL OR manager_id <> id)
);
CREATE INDEX idx_emp_manager ON employees(manager_id);
CREATE INDEX idx_emp_team    ON employees(team_id);

CREATE TABLE leave_types (
  code         TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  yearly_quota REAL NOT NULL
);
INSERT INTO leave_types (code, name, yearly_quota) VALUES
  ('annual','Annual',18), ('sick','Sick',10), ('casual','Casual',8);

CREATE TABLE holidays (
  id   INTEGER PRIMARY KEY,
  date TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL
);
INSERT INTO holidays (date, name) VALUES
  ('2026-01-01','New Year’s Day'), ('2026-01-26','Republic Day'), ('2026-03-04','Holi'),
  ('2026-05-01','Labour Day'), ('2026-08-15','Independence Day'), ('2026-10-02','Gandhi Jayanti'),
  ('2026-10-20','Dussehra'), ('2026-11-08','Diwali'), ('2026-11-09','Diwali (Day 2)'), ('2026-12-25','Christmas');

CREATE TABLE requests (
  id              INTEGER PRIMARY KEY,
  request_no      TEXT NOT NULL UNIQUE,
  kind            TEXT NOT NULL CHECK (kind IN ('leave','wfh')),
  employee_id     INTEGER NOT NULL REFERENCES employees(id),
  approver_id     INTEGER NOT NULL REFERENCES employees(id),
  leave_type      TEXT REFERENCES leave_types(code),
  start_date      TEXT NOT NULL,
  end_date        TEXT NOT NULL,
  is_half_day     INTEGER NOT NULL DEFAULT 0,
  days            REAL NOT NULL,
  reason          TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending','Approved','Rejected','Cancelled')),
  decision_reason TEXT,
  decided_by      INTEGER REFERENCES employees(id),
  decided_at      TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  CHECK (end_date >= start_date),
  CHECK ((kind = 'leave' AND leave_type IS NOT NULL) OR (kind = 'wfh' AND leave_type IS NULL)),
  CHECK (status <> 'Rejected' OR decision_reason IS NOT NULL)
);
CREATE INDEX idx_req_employee ON requests(employee_id, status);
CREATE INDEX idx_req_approver ON requests(approver_id, status);
CREATE INDEX idx_req_dates    ON requests(start_date, end_date);

CREATE TABLE request_history (
  id         INTEGER PRIMARY KEY,
  request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  action     TEXT NOT NULL,
  actor_id   INTEGER REFERENCES employees(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_hist_req ON request_history(request_id);

CREATE TABLE notifications (
  id          INTEGER PRIMARY KEY,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  request_id  INTEGER REFERENCES requests(id),
  message     TEXT NOT NULL,
  is_read     INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_notif_emp ON notifications(employee_id, is_read);

CREATE TABLE attendance_imports (
  id          INTEGER PRIMARY KEY,
  file_name   TEXT NOT NULL,
  uploaded_by INTEGER NOT NULL REFERENCES employees(id),
  uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
  total_rows  INTEGER NOT NULL,
  valid_rows  INTEGER NOT NULL,
  error_rows  INTEGER NOT NULL DEFAULT 0,
  overwritten INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE attendance (
  id          INTEGER PRIMARY KEY,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  date        TEXT NOT NULL,
  status      TEXT NOT NULL CHECK (status IN ('present','late','absent','half_day','wfh','leave')),
  check_in    TEXT,
  check_out   TEXT,
  import_id   INTEGER REFERENCES attendance_imports(id),
  UNIQUE (employee_id, date)
);
CREATE INDEX idx_att_date ON attendance(date);

CREATE TABLE sessions (
  token_hash  TEXT PRIMARY KEY,
  employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  expires_at  TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE audit_log (
  id         INTEGER PRIMARY KEY,
  actor_id   INTEGER REFERENCES employees(id),
  action     TEXT NOT NULL,
  details    TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_audit_time ON audit_log(created_at);
