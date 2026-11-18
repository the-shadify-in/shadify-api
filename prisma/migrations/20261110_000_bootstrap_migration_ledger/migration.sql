DO $$
DECLARE
    v_col_count INT;
    v_pk_cols INT;
    v_has_applied_default BOOLEAN;
BEGIN
    IF to_regclass('public.schema_migrations') IS NOT NULL THEN
        -- 1. Verify column count is exactly 5
        SELECT count(*) INTO v_col_count
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'schema_migrations';

        IF v_col_count != 5 THEN
            RAISE EXCEPTION 'Table public.schema_migrations column count (%) != 5', v_col_count;
        END IF;

        -- 2. Validate all 5 columns with exact types, lengths, and nullability
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'schema_migrations'
              AND column_name = 'version' AND data_type = 'character varying' AND character_maximum_length = 64 AND is_nullable = 'NO'
        ) OR NOT EXISTS (
            SELECT 1 FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'schema_migrations'
              AND column_name = 'name' AND data_type = 'character varying' AND character_maximum_length = 255 AND is_nullable = 'NO'
        ) OR NOT EXISTS (
            SELECT 1 FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'schema_migrations'
              AND column_name = 'checksum' AND data_type = 'character varying' AND character_maximum_length = 64 AND is_nullable = 'NO'
        ) OR NOT EXISTS (
            SELECT 1 FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'schema_migrations'
              AND column_name = 'applied_at' AND data_type = 'timestamp with time zone' AND is_nullable = 'NO'
        ) OR NOT EXISTS (
            SELECT 1 FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'schema_migrations'
              AND column_name = 'rolled_back_at' AND data_type = 'timestamp with time zone' AND is_nullable = 'YES'
        ) THEN
            RAISE EXCEPTION 'Table public.schema_migrations exists but column definitions deviate from specification!';
        END IF;

        -- 3. Verify applied_at has default expression
        SELECT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = 'schema_migrations'
              AND column_name = 'applied_at' AND column_default IS NOT NULL
        ) INTO v_has_applied_default;

        IF NOT v_has_applied_default THEN
            RAISE EXCEPTION 'Table public.schema_migrations missing default on applied_at!';
        END IF;

        -- 4. Verify primary key constraint is strictly on version alone
        SELECT count(*) INTO v_pk_cols
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
        WHERE tc.table_schema = 'public' AND tc.table_name = 'schema_migrations'
          AND tc.constraint_type = 'PRIMARY KEY';

        IF v_pk_cols != 1 THEN
            RAISE EXCEPTION 'Primary key on public.schema_migrations must have exactly 1 column, found %', v_pk_cols;
        END IF;

        IF NOT EXISTS (
            SELECT 1 FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
            WHERE tc.table_schema = 'public' AND tc.table_name = 'schema_migrations'
              AND tc.constraint_type = 'PRIMARY KEY' AND kcu.column_name = 'version'
        ) THEN
            RAISE EXCEPTION 'Primary key on public.schema_migrations must be strictly on version!';
        END IF;
    ELSE
        CREATE TABLE public.schema_migrations (
            version VARCHAR(64) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            checksum VARCHAR(64) NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            rolled_back_at TIMESTAMPTZ NULL
        );
    END IF;
END $$;

