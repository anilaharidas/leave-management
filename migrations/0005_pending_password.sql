-- The new password a person chose on the Forgot password page, waiting for confirmation
ALTER TABLE reset_requests ADD COLUMN new_hash TEXT;
