-- Synchronizer CSRF token, held on the session it protects so that revocation,
-- rotation and expiry govern it without a second lifecycle.

-- The value is stored as issued because the server has to hand it back. It is not
-- a session credential: it proves a request came from a page the server served,
-- never who the caller is.

ALTER TABLE account_sessions
    ADD COLUMN csrf_token text;

-- A session issued before this policy existed carries no token and may not be
-- carried into the protected regime, so it is revoked rather than completed. The
-- value written is drawn by the server CSPRNG and is unusable on a revoked row.
UPDATE account_sessions
SET csrf_token = substr(replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''), 1, 43),
    revoked_at = COALESCE(revoked_at, now())
WHERE csrf_token IS NULL;

ALTER TABLE account_sessions
    ALTER COLUMN csrf_token SET NOT NULL;

ALTER TABLE account_sessions
    ADD CONSTRAINT account_sessions_csrf_token_shape
        CHECK (char_length(csrf_token) = 43);
