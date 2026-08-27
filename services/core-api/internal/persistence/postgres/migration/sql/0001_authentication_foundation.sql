-- Authentication foundation: accounts, login identities, password credentials,
-- role grants, server-side sessions and authentication security events.

-- Identifiers come from the application, random and non-sequential rather than
-- from a sequence. They are not secrets and authorise nothing on their own.

CREATE TABLE accounts (
    id            uuid        PRIMARY KEY,
    kind          text        NOT NULL,
    status        text        NOT NULL,
    display_name  text,
    created_at    timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL,
    CONSTRAINT accounts_kind_known
        CHECK (kind IN ('viewer', 'creator', 'operator')),
    CONSTRAINT accounts_status_known
        CHECK (status IN ('pending', 'active', 'suspended', 'closed')),
    CONSTRAINT accounts_display_name_shape
        CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 64)
);

-- display_name is not unique and is not an addressable identifier. A public
-- handle, if one is ever adopted, is a separate concept with its own rules.

-- The login address is separated from the public identity and from the account
-- identifier, so changing one never changes another.
CREATE TABLE account_email_identities (
    id          uuid        PRIMARY KEY,
    account_id  uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    address     text        NOT NULL,
    verified_at timestamptz,
    created_at  timestamptz NOT NULL,
    CONSTRAINT account_email_identities_address_shape
        CHECK (length(address) BETWEEN 3 AND 254 AND address = lower(address))
);

CREATE UNIQUE INDEX account_email_identities_address_unique
    ON account_email_identities (address);
CREATE INDEX account_email_identities_account
    ON account_email_identities (account_id);

-- The encoded hash carries its own algorithm, version and parameters, so a
-- stored credential remains verifiable after the adopted parameters change.
CREATE TABLE account_password_credentials (
    account_id   uuid        PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    encoded_hash text        NOT NULL,
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    CONSTRAINT account_password_credentials_encoded_shape
        CHECK (encoded_hash LIKE '$argon2id$%' AND length(encoded_hash) BETWEEN 32 AND 512)
);

-- Privileges are granted as rows rather than as one column, so an account can
-- carry several and the set can grow without rewriting the account.
CREATE TABLE account_role_grants (
    account_id uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    role       text        NOT NULL,
    granted_at timestamptz NOT NULL,
    PRIMARY KEY (account_id, role),
    CONSTRAINT account_role_grants_role_known
        CHECK (role IN (
            'viewer',
            'creator',
            'operator_support',
            'operator_moderation',
            'operator_compliance',
            'operator_finance'
        ))
);

-- Only an irreversible fingerprint of the session token is stored. The token
-- itself never reaches the database.
CREATE TABLE account_sessions (
    id                  uuid        PRIMARY KEY,
    account_id          uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    token_fingerprint   bytea       NOT NULL,
    surface             text        NOT NULL,
    created_at          timestamptz NOT NULL,
    last_active_at      timestamptz NOT NULL,
    idle_expires_at     timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at          timestamptz,
    rotated_to          uuid REFERENCES account_sessions (id) ON DELETE SET NULL,
    CONSTRAINT account_sessions_surface_known
        CHECK (surface IN ('public', 'operator')),
    CONSTRAINT account_sessions_fingerprint_shape
        CHECK (octet_length(token_fingerprint) = 32),
    CONSTRAINT account_sessions_absolute_after_creation
        CHECK (absolute_expires_at > created_at),
    CONSTRAINT account_sessions_idle_within_absolute
        CHECK (idle_expires_at <= absolute_expires_at)
);

CREATE UNIQUE INDEX account_sessions_fingerprint_unique
    ON account_sessions (token_fingerprint);
CREATE INDEX account_sessions_account_live
    ON account_sessions (account_id) WHERE revoked_at IS NULL;

-- Security events record that something happened, never the material involved.
CREATE TABLE account_security_events (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id  uuid        REFERENCES accounts (id) ON DELETE SET NULL,
    session_id  uuid        REFERENCES account_sessions (id) ON DELETE SET NULL,
    kind        text        NOT NULL,
    occurred_at timestamptz NOT NULL,
    CONSTRAINT account_security_events_kind_known
        CHECK (kind IN (
            'credential_created',
            'credential_changed',
            'session_created',
            'session_rotated',
            'session_revoked',
            'sessions_revoked_for_account',
            'account_suspended'
        ))
);

CREATE INDEX account_security_events_account_time
    ON account_security_events (account_id, occurred_at DESC);
