-- The column was created as "verify_token" in 000003, but every query in the
-- service reads and writes "verification_code". Registration and login both
-- failed with 42703 (undefined_column) as soon as the verification flow went
-- live. Renaming is the smaller change: the code name is used in five places
-- and matches the domain model field.
--
-- Guarded so it is safe on a database that has already been corrected by hand.

-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'verify_token'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'verification_code'
    ) THEN
        ALTER TABLE users RENAME COLUMN verify_token TO verification_code;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'verification_code'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'verify_token'
    ) THEN
        ALTER TABLE users RENAME COLUMN verification_code TO verify_token;
    END IF;
END
$$;
-- +goose StatementEnd
