-- A monotonic revision on the stored credential, so a password verified before a
-- replacement can never create a session after it.

-- Added with a default so every existing row is backfilled without a rewrite,
-- then the default is removed: from here on a writer must state the revision it
-- means, and one that forgets fails the NOT NULL rather than silently starting
-- over at 1.
ALTER TABLE account_password_credentials
    ADD COLUMN revision bigint NOT NULL DEFAULT 1;

ALTER TABLE account_password_credentials
    ALTER COLUMN revision DROP DEFAULT;

ALTER TABLE account_password_credentials
    ADD CONSTRAINT account_password_credentials_revision_positive
        CHECK (revision >= 1);
