-- Public viewer registration: the challenge that proves control of a login
-- address, and the outbox that carries it to that address exactly once or more.

-- Proving control of a mailbox is all a challenge establishes. It is neither an
-- age assurance nor an identity proof, and it grants no capability of its own.

CREATE TABLE account_email_verifications (
    id                uuid        PRIMARY KEY,
    identity_id       uuid        NOT NULL REFERENCES account_email_identities (id) ON DELETE CASCADE,
    token_fingerprint bytea       NOT NULL,
    issued_at         timestamptz NOT NULL,
    expires_at        timestamptz NOT NULL,
    consumed_at       timestamptz,
    superseded_at     timestamptz,
    CONSTRAINT account_email_verifications_fingerprint_shape
        CHECK (octet_length(token_fingerprint) = 32),
    CONSTRAINT account_email_verifications_expiry_after_issuance
        CHECK (expires_at > issued_at),
    -- Consumption at or after the expiry is a state the reader refuses, so it is
    -- also a state the writer may never produce.
    CONSTRAINT account_email_verifications_consumed_within_life
        CHECK (consumed_at IS NULL OR (consumed_at >= issued_at AND consumed_at < expires_at)),
    -- Supersession is deliberately not bounded by the expiry: an expired
    -- challenge stays current until something supersedes or consumes it.
    CONSTRAINT account_email_verifications_superseded_after_issuance
        CHECK (superseded_at IS NULL OR superseded_at >= issued_at),
    CONSTRAINT account_email_verifications_terminal_states_exclusive
        CHECK (NOT (consumed_at IS NOT NULL AND superseded_at IS NOT NULL))
);

CREATE UNIQUE INDEX account_email_verifications_fingerprint_unique
    ON account_email_verifications (token_fingerprint);

-- At most one current challenge per identity. Current means neither consumed nor
-- superseded; an expired one is still current, so a new issuance must supersede
-- the previous row before inserting its own.
CREATE UNIQUE INDEX account_email_verifications_current_unique
    ON account_email_verifications (identity_id)
    WHERE consumed_at IS NULL AND superseded_at IS NULL;

CREATE INDEX account_email_verifications_current_expiry
    ON account_email_verifications (expires_at)
    WHERE consumed_at IS NULL AND superseded_at IS NULL;

-- The outbox holds work still to be done and nothing else: a row exists exactly
-- while a message may still be sent, so no terminal state and no bearer token is
-- left behind. The address stays on the identity, its single authority.
CREATE TABLE account_email_deliveries (
    id               uuid        PRIMARY KEY,
    challenge_id     uuid        NOT NULL UNIQUE REFERENCES account_email_verifications (id) ON DELETE CASCADE,
    token            text        NOT NULL,
    created_at       timestamptz NOT NULL,
    available_at     timestamptz NOT NULL,
    -- The challenge's expiry, copied at issuance. Nothing ever moves a challenge's
    -- expiry, so the copy cannot drift, and it lets a sweep choose its candidates
    -- on this table alone rather than by joining a history that is never emptied.
    expires_at       timestamptz NOT NULL,
    attempts         integer     NOT NULL DEFAULT 0,
    claimed_at       timestamptz,
    claim_expires_at timestamptz,
    claim_id         uuid,
    CONSTRAINT account_email_deliveries_attempts_non_negative
        CHECK (attempts >= 0),
    CONSTRAINT account_email_deliveries_token_shape
        CHECK (char_length(token) = 43),
    CONSTRAINT account_email_deliveries_available_after_creation
        CHECK (available_at >= created_at),
    CONSTRAINT account_email_deliveries_expiry_after_creation
        CHECK (expires_at > created_at),
    CONSTRAINT account_email_deliveries_claimed_after_creation
        CHECK (claimed_at IS NULL OR claimed_at >= created_at),
    -- The three lease columns are set together or not at all, so no row can carry
    -- half a lease.
    CONSTRAINT account_email_deliveries_lease_deadline_paired
        CHECK ((claimed_at IS NULL) = (claim_expires_at IS NULL)),
    CONSTRAINT account_email_deliveries_lease_owner_paired
        CHECK ((claimed_at IS NULL) = (claim_id IS NULL)),
    CONSTRAINT account_email_deliveries_lease_ordered
        CHECK (claim_expires_at IS NULL OR claim_expires_at > claimed_at)
);

-- Two populations are searched: work never claimed or released back, ordered by
-- the instant it becomes due, and rows whose lease has lapsed.
CREATE INDEX account_email_deliveries_unleased_due
    ON account_email_deliveries (available_at, id)
    WHERE claim_expires_at IS NULL;

CREATE INDEX account_email_deliveries_lease_deadline
    ON account_email_deliveries (claim_expires_at)
    WHERE claim_expires_at IS NOT NULL;

-- The two causes a sweep removes work for. Each is a range on its own column, so
-- a small cleanable lot is reached without walking a queue that is mostly live.
CREATE INDEX account_email_deliveries_expiry
    ON account_email_deliveries (expires_at);

CREATE INDEX account_email_deliveries_attempts
    ON account_email_deliveries (attempts);

ALTER TABLE account_security_events
    DROP CONSTRAINT account_security_events_kind_known;

ALTER TABLE account_security_events
    ADD CONSTRAINT account_security_events_kind_known
        CHECK (kind IN (
            'account_registered',
            'credential_created',
            'credential_changed',
            'email_verification_issued',
            'email_verification_completed',
            'session_created',
            'session_rotated',
            'session_revoked',
            'sessions_revoked_for_account',
            'account_suspended'
        ));
