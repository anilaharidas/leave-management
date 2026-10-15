-- Forgot password: one-time email links, and requests an admin can act on
CREATE TABLE password_resets (
  id          INTEGER PRIMARY KEY,
  employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL UNIQUE,
  expires_at  TEXT NOT NULL,
  used_at     TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_resets_emp ON password_resets(employee_id);

CREATE TABLE reset_requests (
  id          INTEGER PRIMARY KEY,
  employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  status      TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open','Done','Dismissed')),
  emailed     INTEGER NOT NULL DEFAULT 0,
  handled_by  INTEGER REFERENCES employees(id),
  handled_at  TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_reset_req_status ON reset_requests(status, employee_id);
