-- WhatsApp number per employee, and force a password change after an admin sets/resets it
ALTER TABLE employees ADD COLUMN phone TEXT;
ALTER TABLE employees ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;
