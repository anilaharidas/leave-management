-- Weekly offs can be stored, and each person remembers the code their biometric device uses.
CREATE TABLE attendance_new (
  id          INTEGER PRIMARY KEY,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  date        TEXT NOT NULL,
  status      TEXT NOT NULL CHECK (status IN ('present','late','absent','half_day','wfh','leave','weekoff')),
  check_in    TEXT,
  check_out   TEXT,
  import_id   INTEGER REFERENCES attendance_imports(id),
  UNIQUE (employee_id, date)
);
INSERT INTO attendance_new (id, employee_id, date, status, check_in, check_out, import_id)
  SELECT id, employee_id, date, status, check_in, check_out, import_id FROM attendance;
DROP TABLE attendance;
ALTER TABLE attendance_new RENAME TO attendance;
CREATE INDEX idx_att_date ON attendance(date);

ALTER TABLE employees ADD COLUMN biometric_code TEXT;
CREATE UNIQUE INDEX idx_emp_biometric ON employees(biometric_code) WHERE biometric_code IS NOT NULL;
