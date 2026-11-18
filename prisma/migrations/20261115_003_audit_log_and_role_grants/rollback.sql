-- Rollback for 20261115_003_audit_log_and_role_grants
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'shadify_api_role') THEN
        REVOKE SELECT, INSERT ON public.audit_log FROM shadify_api_role;
        REVOKE SELECT, INSERT, UPDATE ON public.operator_identities FROM shadify_api_role;
        REVOKE USAGE, SELECT ON SEQUENCE public.audit_log_id_seq FROM shadify_api_role;
    END IF;
END $$;

DROP INDEX IF EXISTS public.idx_audit_operator;
ALTER TABLE public.audit_log DROP COLUMN IF EXISTS operator_id;
DROP TABLE IF EXISTS public.operator_identities CASCADE;
