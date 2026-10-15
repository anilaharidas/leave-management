-- Counts wrong-password attempts so guessing is slowed down
CREATE TABLE login_attempts (
  key          TEXT PRIMARY KEY,
  fails        INTEGER NOT NULL,
  window_start TEXT NOT NULL,
  locked_until TEXT
);
