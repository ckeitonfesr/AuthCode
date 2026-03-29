ALTER TABLE auth_codes ADD COLUMN IF NOT EXISTS code_hash TEXT;

UPDATE auth_codes SET code_hash = encode(sha256(code::bytea), 'hex') WHERE code_hash IS NULL;

ALTER TABLE auth_codes ALTER COLUMN code_hash SET NOT NULL;

ALTER TABLE auth_codes DROP COLUMN IF EXISTS code;

CREATE INDEX IF NOT EXISTS idx_auth_codes_email ON auth_codes(email);
CREATE INDEX IF NOT EXISTS idx_api_tokens_device ON api_tokens(device_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_created ON api_tokens(created_at);
