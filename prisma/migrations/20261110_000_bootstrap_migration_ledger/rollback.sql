DO $$
BEGIN
    IF to_regclass('public.schema_migrations') IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM pg_depend d
            JOIN pg_class c ON d.objid = c.oid
            WHERE d.refobjid = 'public.schema_migrations'::regclass
              AND d.deptype = 'n'
              AND c.relname != 'schema_migrations'
        ) THEN
            RAISE EXCEPTION 'Cannot drop public.schema_migrations: external dependent objects exist!';
        END IF;

        DROP TABLE public.schema_migrations;
    END IF;
END $$;

