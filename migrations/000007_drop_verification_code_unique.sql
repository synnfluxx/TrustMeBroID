-- The column was created UNIQUE when it held a 32 byte token, where a
-- collision is impossible. A six digit code has a million values and is never
-- cleared, so every account permanently occupies one: by the birthday bound a
-- collision becomes more likely than not at around 1200 users, and each one is
-- a registration failing on a constraint the user can do nothing about.
--
-- The constraint was never doing any work. Two accounts holding the same
-- pending code is harmless: the code is only ever checked against the row
-- found by email.

-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    name text;
BEGIN
    SELECT conname INTO name
    FROM pg_constraint
    WHERE conrelid = 'users'::regclass
      AND contype = 'u'
      AND conkey = ARRAY[(
          SELECT attnum FROM pg_attribute
          WHERE attrelid = 'users'::regclass AND attname = 'verification_code'
      )]::smallint[];

    IF name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE users DROP CONSTRAINT %I', name);
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Deliberately not restored: re-adding it would fail on any database that has
-- since collected duplicate codes, which is the state this migration allows.
SELECT 1;
-- +goose StatementEnd
