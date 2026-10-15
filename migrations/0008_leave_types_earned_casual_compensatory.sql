-- Leave types become: Earned, Casual, Compensatory.
-- Rows are never deleted (past requests refer to them): Annual is renamed, Sick and anything else is switched off.
UPDATE leave_types SET name = 'Earned', is_active = 1 WHERE code = 'annual';
UPDATE leave_types SET is_active = 1 WHERE code = 'casual';

INSERT OR IGNORE INTO leave_types (code, name, yearly_quota, is_active) VALUES ('compensatory', 'Compensatory', 3, 1);
INSERT OR IGNORE INTO leave_quotas (leave_type, role, quota) VALUES ('compensatory', 'employee', 3);
INSERT OR IGNORE INTO leave_quotas (leave_type, role, quota) VALUES ('compensatory', 'manager', 3);
UPDATE leave_types SET name = 'Compensatory', is_active = 1 WHERE code = 'compensatory';

UPDATE leave_types SET is_active = 0 WHERE code NOT IN ('annual', 'casual', 'compensatory');
