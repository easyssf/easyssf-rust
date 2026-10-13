-- Tables of the JDBC stores of the easyssf receiver, as this release expects them (a fresh installation).
-- Timestamps are milliseconds since the epoch. On Oracle use NUMBER(19) instead of BIGINT.
-- Installations that migrate from release to release use the scripts in migration/ instead, one per release
-- that changed the schema, named for Flyway.

-- SETs that were processed or are being processed (STATE 'PROCESSED' / 'IN_PROGRESS', STATE_CHANGED_AT the time
-- of the last state change, which also fences the claim), see JdbcSsfJtiDedupStore.
CREATE TABLE EASYSSF_PROCESSED_SET (
    ISSUER VARCHAR(255) NOT NULL,
    JTI VARCHAR(255) NOT NULL,
    STATE VARCHAR(16) NOT NULL,
    STATE_CHANGED_AT BIGINT NOT NULL,
    CONSTRAINT EASYSSF_PROCESSED_SET_PK PRIMARY KEY (ISSUER, JTI)
);
CREATE INDEX EASYSSF_PROCESSED_SET_IX1 ON EASYSSF_PROCESSED_SET (STATE_CHANGED_AT);

-- revoked sessions (KIND 'SESSION') and subjects (KIND 'SUBJECT') of an issuer, see JdbcSsfTokenRevocationStore
CREATE TABLE EASYSSF_REVOCATION (
    KIND VARCHAR(16) NOT NULL,
    ISSUER VARCHAR(255) NOT NULL,
    ID VARCHAR(255) NOT NULL,
    REVOKED_AT BIGINT NOT NULL,
    EXPIRES_AT BIGINT NOT NULL,
    CONSTRAINT EASYSSF_REVOCATION_PK PRIMARY KEY (KIND, ISSUER, ID)
);
CREATE INDEX EASYSSF_REVOCATION_IX1 ON EASYSSF_REVOCATION (EXPIRES_AT);

-- acknowledgements and error reports a poller owes its transmitter until a poll request carried them,
-- see JdbcSsfPollAckStore (ERROR_CODE NULL: acknowledgement)
CREATE TABLE EASYSSF_POLL_ACK (
    ISSUER VARCHAR(255) NOT NULL,
    JTI VARCHAR(255) NOT NULL,
    ERROR_CODE VARCHAR(64),
    ERROR_DESCRIPTION VARCHAR(1024),
    RECORDED_AT BIGINT NOT NULL,
    CONSTRAINT EASYSSF_POLL_ACK_PK PRIMARY KEY (ISSUER, JTI)
);
CREATE INDEX EASYSSF_POLL_ACK_IX1 ON EASYSSF_POLL_ACK (RECORDED_AT);
