-- Admin-managed leave allowances per leave type and per role (admins use the manager column)
ALTER TABLE leave_types ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1;

CREATE TABLE leave_quotas (
  leave_type TEXT NOT NULL REFERENCES leave_types(code),
  role       TEXT NOT NULL CHECK (role IN ('employee','manager')),
  quota      REAL NOT NULL CHECK (quota >= 0),
  PRIMARY KEY (leave_type, role)
);
INSERT INTO leave_quotas (leave_type, role, quota) SELECT code, 'employee', yearly_quota FROM leave_types;
INSERT INTO leave_quotas (leave_type, role, quota) SELECT code, 'manager',  yearly_quota FROM leave_types;
