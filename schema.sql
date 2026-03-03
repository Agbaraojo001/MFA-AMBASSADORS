-- ================================================================
--  MFA AMBASSADORS 2026 - SUPABASE POSTGRESQL SCHEMA
--  Run this ONCE in: Supabase Dashboard > SQL Editor > New Query
--  Paste the entire file and click RUN
-- ================================================================

-- 1. ATOMIC COUNTER
--    One row, incremented atomically per registration.
--    Guarantees unique sequential codes even under concurrent load.
CREATE TABLE IF NOT EXISTS reg_counter (
  id          INT  PRIMARY KEY DEFAULT 1,
  current_val INT  NOT NULL DEFAULT 0,
  CONSTRAINT single_row CHECK (id = 1)
);
INSERT INTO reg_counter (id, current_val)
VALUES (1, 0)
ON CONFLICT (id) DO NOTHING;


-- 2. REGISTRATIONS TABLE
CREATE TABLE IF NOT EXISTS registrations (
  id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  reg_code          TEXT        UNIQUE NOT NULL,
  surname           TEXT        NOT NULL,
  other_names       TEXT        NOT NULL,
  gender            TEXT        NOT NULL,
  telephone         TEXT        NOT NULL,
  lga               TEXT,
  town              TEXT,
  occupation        TEXT,
  apc_membership_no TEXT,
  voters_card_no    TEXT,
  availability      TEXT        NOT NULL,
  ip_address        TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE registrations
  ADD CONSTRAINT chk_gender       CHECK (gender       IN ('Male','Female')),
  ADD CONSTRAINT chk_availability CHECK (availability IN ('Yes','No')),
  ADD CONSTRAINT chk_surname_len  CHECK (char_length(surname)     BETWEEN 2 AND 100),
  ADD CONSTRAINT chk_othname_len  CHECK (char_length(other_names) BETWEEN 2 AND 150),
  ADD CONSTRAINT chk_phone_len    CHECK (char_length(telephone)   BETWEEN 7  AND 20);

-- One registration per phone number
CREATE UNIQUE INDEX IF NOT EXISTS idx_reg_telephone ON registrations (telephone);
CREATE        INDEX IF NOT EXISTS idx_reg_created   ON registrations (created_at DESC);


-- 3. ATOMIC CODE-GENERATION FUNCTION
--    FOR UPDATE row-lock ensures two concurrent requests
--    can never receive the same code number.
CREATE OR REPLACE FUNCTION get_next_reg_code()
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  next_val INT;
BEGIN
  UPDATE reg_counter
     SET current_val = current_val + 1
   WHERE id = 1
   RETURNING current_val INTO next_val;

  RETURN 'AMB-2026-' || LPAD(next_val::TEXT, 5, '0');
END;
$$;


-- 4. ROW-LEVEL SECURITY
--    Service-role key (backend only) bypasses RLS.
--    Anon/public key has ZERO direct table access.
ALTER TABLE registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE reg_counter   ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service_role_registrations"
  ON registrations FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "service_role_counter"
  ON reg_counter FOR ALL USING (auth.role() = 'service_role');


-- 5. RATE-LIMIT AUDIT LOG
CREATE TABLE IF NOT EXISTS reg_attempts (
  id           BIGSERIAL   PRIMARY KEY,
  ip_address   TEXT        NOT NULL,
  attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_attempts_ip_time
  ON reg_attempts (ip_address, attempted_at DESC);

ALTER TABLE reg_attempts ENABLE ROW LEVEL SECURITY;
CREATE POLICY "service_role_attempts"
  ON reg_attempts FOR ALL USING (auth.role() = 'service_role');
