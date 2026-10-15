-- A person can hold several roles at once (employee, manager, admin).
-- `role` stays as the highest role for display; `roles` is the full set.
ALTER TABLE employees ADD COLUMN roles TEXT NOT NULL DEFAULT 'employee';
UPDATE employees SET roles = CASE role
  WHEN 'admin'   THEN 'admin,manager,employee'
  WHEN 'manager' THEN 'manager,employee'
  ELSE 'employee' END;
