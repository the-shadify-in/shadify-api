-- Migration: 20261115_002_security_fencing_and_revocation_ledger
-- Direction: Down (Rollback)
-- Description: Reverts security fencing, revocation lists, guest rate limiting, and stored procedures.

-- 1. Drop Stored Procedures
DROP FUNCTION IF EXISTS public.cancel_upload_session(BIGINT);
DROP FUNCTION IF EXISTS public.claim_verification_lease(BIGINT, TEXT);
DROP FUNCTION IF EXISTS public.claim_verification_lease(BIGINT, TEXT, INT);
DROP FUNCTION IF EXISTS public.complete_upload_session(BIGINT, BIGINT, TEXT);
DROP FUNCTION IF EXISTS public.complete_upload_session(BIGINT, BIGINT, TEXT, INT, TEXT);

-- 2. Drop Constraints and Columns from photos
ALTER TABLE public.photos DROP CONSTRAINT IF EXISTS photos_upload_session_id_fkey;
ALTER TABLE public.photos DROP CONSTRAINT IF EXISTS uq_photos_session;
ALTER TABLE public.photos DROP COLUMN IF EXISTS upload_session_id;

-- 3. Drop Columns from upload_sessions
ALTER TABLE public.upload_sessions DROP COLUMN IF EXISTS verification_lease_expires_at;
ALTER TABLE public.upload_sessions DROP COLUMN IF EXISTS verification_lease_token;
ALTER TABLE public.upload_sessions DROP COLUMN IF EXISTS verification_generation;

-- 4. Drop Tables
DROP TABLE IF EXISTS public.revoked_guest_tokens CASCADE;
DROP TABLE IF EXISTS public.guest_pin_attempts CASCADE;
DROP TABLE IF EXISTS public.revoked_operators CASCADE;
DROP TABLE IF EXISTS public.revoked_delegation_keys CASCADE;
DROP TABLE IF EXISTS public.delegation_jti_registry CASCADE;

