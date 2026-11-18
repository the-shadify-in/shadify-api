-- Migration: 20261115_003_audit_log_and_role_grants
-- Direction: Up (Idempotent, non-breaking)
-- Description: Creates operator_identities table, adds operator_id to audit_log with RESTRICT foreign key, and enforces append-only permissions for shadify_api_role.

-- 1. Ensure baseline audit_log table exists matching 0_init definition
CREATE TABLE IF NOT EXISTS public.audit_log (
    id BIGSERIAL PRIMARY KEY,
    wedding_id UUID NULL REFERENCES public.weddings(id) ON DELETE SET NULL,
    actor_id UUID NULL REFERENCES public.users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    detail JSONB NULL,
    created_at TIMESTAMPTZ(6) NOT NULL DEFAULT clock_timestamp()
);

-- 2. Create durable operator_identities table for administrative and system actors
CREATE TABLE IF NOT EXISTS public.operator_identities (
    id UUID PRIMARY KEY,
    operator_user_id TEXT UNIQUE NOT NULL,
    authoritative_role TEXT NOT NULL,
    created_at TIMESTAMPTZ(6) NOT NULL DEFAULT clock_timestamp()
);

-- 3. Add operator_id referencing operator_identities with ON DELETE RESTRICT
ALTER TABLE public.audit_log 
    ADD COLUMN IF NOT EXISTS wedding_id UUID NULL REFERENCES public.weddings(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS actor_id UUID NULL REFERENCES public.users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS action TEXT,
    ADD COLUMN IF NOT EXISTS detail JSONB NULL,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ(6) NOT NULL DEFAULT clock_timestamp(),
    ADD COLUMN IF NOT EXISTS operator_id UUID NULL;

-- Reconcile column definitions, types, and defaults
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'audit_log' AND column_name = 'operator_id' AND data_type <> 'uuid'
    ) THEN
        ALTER TABLE public.audit_log ALTER COLUMN operator_id TYPE UUID USING operator_id::UUID;
    END IF;
    ALTER TABLE public.audit_log ALTER COLUMN operator_id DROP NOT NULL;
    ALTER TABLE public.audit_log ALTER COLUMN created_at SET DEFAULT clock_timestamp();
    ALTER TABLE public.audit_log ALTER COLUMN created_at SET NOT NULL;
END $$;

-- Ensure foreign key constraint is explicitly active on operator_id with ON DELETE RESTRICT
-- Correlates exact source attribute (operator_id) and referenced attribute (id) in schema public with confdeltype = 'r'
-- Unconditionally cleans up any stale or incorrect foreign key constraints on operator_id even if a valid one exists!
DO $$
DECLARE
    valid_fk TEXT;
    stale_rec RECORD;
BEGIN
    -- 0. Fail-closed safeguard: If a non-foreign-key constraint (CHECK, UNIQUE, etc.) already occupies
    -- the canonical name 'fk_audit_log_operator_id', fail closed immediately with an informative exception
    -- rather than modifying other constraints or failing with an ambiguous PostgreSQL constraint error.
    IF EXISTS (
        SELECT 1 FROM pg_constraint con
        JOIN pg_class c_src ON c_src.oid = con.conrelid
        JOIN pg_namespace n_src ON n_src.oid = c_src.relnamespace
        WHERE n_src.nspname = 'public'
          AND c_src.relname = 'audit_log'
          AND con.conname = 'fk_audit_log_operator_id'
          AND con.contype <> 'f'
    ) THEN
        RAISE EXCEPTION 'CANONICAL_CONSTRAINT_NAME_OCCUPIED: Non-foreign-key constraint occupies fk_audit_log_operator_id on audit_log';
    END IF;

    -- 1. Identify valid matching foreign key: public.audit_log(operator_id) -> public.operator_identities(id)
    -- Must have ON UPDATE RESTRICT ('r'), ON DELETE RESTRICT ('r'), single key, and convalidated = true
    SELECT con.conname INTO valid_fk
    FROM pg_constraint con
    JOIN pg_class c_src ON c_src.oid = con.conrelid
    JOIN pg_namespace n_src ON n_src.oid = c_src.relnamespace
    JOIN pg_class c_ref ON c_ref.oid = con.confrelid
    JOIN pg_namespace n_ref ON n_ref.oid = c_ref.relnamespace
    JOIN pg_attribute a_src ON a_src.attrelid = c_src.oid AND a_src.attnum = con.conkey[1]
    JOIN pg_attribute a_ref ON a_ref.attrelid = c_ref.oid AND a_ref.attnum = con.confkey[1]
    WHERE con.contype = 'f'
      AND n_src.nspname = 'public'
      AND c_src.relname = 'audit_log'
      AND a_src.attname = 'operator_id'
      AND n_ref.nspname = 'public'
      AND c_ref.relname = 'operator_identities'
      AND a_ref.attname = 'id'
      AND con.confupdtype = 'r'
      AND con.confdeltype = 'r'
      AND array_length(con.conkey, 1) = 1
      AND array_length(con.confkey, 1) = 1
      AND con.convalidated = true;

    -- 2. Drop ANY other foreign key constraint on audit_log where operator_id occurs anywhere in conkey
    -- (catches composite FKs where operator_id is at position 2+, unvalidated NOT VALID constraints, etc.)
    FOR stale_rec IN (
        SELECT DISTINCT con.conname
        FROM pg_constraint con
        JOIN pg_class c_src ON c_src.oid = con.conrelid
        JOIN pg_namespace n_src ON n_src.oid = c_src.relnamespace
        JOIN pg_attribute a_src ON a_src.attrelid = c_src.oid AND a_src.attnum = ANY(con.conkey)
        WHERE con.contype = 'f'
          AND n_src.nspname = 'public'
          AND c_src.relname = 'audit_log'
          AND a_src.attname = 'operator_id'
          AND (valid_fk IS NULL OR con.conname <> valid_fk)
    ) LOOP
        EXECUTE 'ALTER TABLE public.audit_log DROP CONSTRAINT ' || quote_ident(stale_rec.conname);
    END LOOP;

    -- 3. If any FOREIGN KEY constraint named 'fk_audit_log_operator_id' exists on audit_log that is NOT valid_fk,
    -- drop it to prevent name collisions. Non-foreign-key constraints (CHECK, UNIQUE) are never dropped.
    IF EXISTS (
        SELECT 1 FROM pg_constraint con
        JOIN pg_class c_src ON c_src.oid = con.conrelid
        JOIN pg_namespace n_src ON n_src.oid = c_src.relnamespace
        WHERE n_src.nspname = 'public'
          AND c_src.relname = 'audit_log'
          AND con.contype = 'f'
          AND con.conname = 'fk_audit_log_operator_id'
          AND (valid_fk IS NULL OR valid_fk <> 'fk_audit_log_operator_id')
    ) THEN
        ALTER TABLE public.audit_log DROP CONSTRAINT fk_audit_log_operator_id;
    END IF;

    -- 4. Ensure canonical constraint exists with canonical name 'fk_audit_log_operator_id'
    IF valid_fk IS NULL THEN
        ALTER TABLE public.audit_log 
            ADD CONSTRAINT fk_audit_log_operator_id 
            FOREIGN KEY (operator_id) REFERENCES public.operator_identities(id) 
            ON UPDATE RESTRICT
            ON DELETE RESTRICT;
    ELSIF valid_fk <> 'fk_audit_log_operator_id' THEN
        -- Valid matching constraint exists under a non-canonical name: rename to canonical name
        EXECUTE 'ALTER TABLE public.audit_log RENAME CONSTRAINT ' || quote_ident(valid_fk) || ' TO fk_audit_log_operator_id';
    END IF;
END $$;

-- 4. Create performance indexes
CREATE INDEX IF NOT EXISTS idx_audit_wedding ON public.audit_log(wedding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_operator ON public.audit_log(operator_id);

-- 5. Grant append-only privileges to runtime role shadify_api_role
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'shadify_api_role') THEN
        GRANT USAGE ON SCHEMA public TO shadify_api_role;
        GRANT SELECT, INSERT ON public.audit_log TO shadify_api_role;
        GRANT SELECT, INSERT, UPDATE ON public.operator_identities TO shadify_api_role;
        GRANT USAGE, SELECT ON SEQUENCE public.audit_log_id_seq TO shadify_api_role;
        REVOKE UPDATE, DELETE, TRUNCATE ON public.audit_log FROM shadify_api_role;
        REVOKE DELETE, TRUNCATE ON public.operator_identities FROM shadify_api_role;
    END IF;
END $$;
