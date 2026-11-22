CREATE TABLE
    IF NOT EXISTS refresh_tokens (
        id UUID PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        family_id UUID NOT NULL,
        token_hash VARCHAR(64) UNIQUE NOT NULL,
        expires_at TIMESTAMP
        WITH
            TIME ZONE NOT NULL,
            revoked_at TIMESTAMP
        WITH
            TIME ZONE,
            created_at TIMESTAMP
        WITH
            TIME ZONE NOT NULL
    );

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens (user_id);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id ON refresh_tokens (family_id);