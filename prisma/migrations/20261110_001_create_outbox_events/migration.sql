CREATE TABLE public.outbox_events (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    wedding_id UUID NOT NULL REFERENCES public.weddings(id) ON DELETE CASCADE,
    photo_id UUID NULL REFERENCES public.photos(id) ON DELETE SET NULL,
    generation_token BIGINT NOT NULL DEFAULT 1,
    payload JSONB NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    retry_count INT NOT NULL DEFAULT 0,
    max_retries INT NOT NULL DEFAULT 4,
    last_error TEXT NULL,
    lease_token UUID NULL,
    lease_expires_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX idx_outbox_events_polling
    ON public.outbox_events (status, created_at)
    WHERE status IN ('PENDING', 'PROCESSING');

CREATE INDEX idx_outbox_events_wedding_photo
    ON public.outbox_events (wedding_id, photo_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.outbox_events TO shadify_api_role;
GRANT USAGE, SELECT ON SEQUENCE public.outbox_events_id_seq TO shadify_api_role;
REVOKE UPDATE ON SEQUENCE public.outbox_events_id_seq FROM shadify_api_role;
