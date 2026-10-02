-- 000004 created "last_token_generated_time" and it is applied everywhere the
-- service runs. Editing that file renames nothing: goose only replays versions
-- it has not recorded, so a corrected 000004 reaches a fresh database and never
-- an existing one. The code would then ask for a column production does not
-- have — which is exactly how "verify_token" reached a running environment.
--
-- Guarded, so it is also safe where the column was already corrected by hand.

-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'last_token_generated_time'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'last_code_generated_time'
    ) THEN
        ALTER TABLE users RENAME COLUMN last_token_generated_time TO last_code_generated_time;
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
        WHERE table_name = 'users' AND column_name = 'last_code_generated_time'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'last_token_generated_time'
    ) THEN
        ALTER TABLE users RENAME COLUMN last_code_generated_time TO last_token_generated_time;
    END IF;
END
$$;
-- +goose StatementEnd
