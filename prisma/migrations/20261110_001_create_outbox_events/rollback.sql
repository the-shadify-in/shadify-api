DO $$
BEGIN
    IF to_regclass('public.outbox_events') IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM pg_depend d
            JOIN pg_class c ON d.objid = c.oid
            WHERE d.refobjid = 'public.outbox_events'::regclass
              AND d.deptype = 'n'
              AND c.relname NOT IN ('outbox_events', 'idx_outbox_events_polling', 'idx_outbox_events_wedding_photo', 'outbox_events_id_seq')
        ) THEN
            RAISE EXCEPTION 'Cannot drop public.outbox_events: unexpected external dependent objects exist!';
        END IF;

        DROP INDEX IF EXISTS public.idx_outbox_events_wedding_photo;
        DROP INDEX IF EXISTS public.idx_outbox_events_polling;
        DROP TABLE public.outbox_events;

        UPDATE public.schema_migrations
        SET rolled_back_at = clock_timestamp()
        WHERE version = '20261110_001' AND rolled_back_at IS NULL;
        
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Expected 1 active ledger record for 20261110_001 on rollback, but none found!';
        END IF;
    END IF;
END $$;

