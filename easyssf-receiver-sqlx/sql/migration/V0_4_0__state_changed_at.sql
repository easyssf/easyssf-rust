-- easyssf 0.4.0: PROCESSED_AT of EASYSSF_PROCESSED_SET becomes STATE_CHANGED_AT. The column has recorded the time
-- of the claim as well as that of the completion since 0.3.0, and it fences the claim; the name now says so.
-- RENAME COLUMN is supported by H2, PostgreSQL and MySQL 8; the index EASYSSF_PROCESSED_SET_IX1 follows the column.

ALTER TABLE EASYSSF_PROCESSED_SET RENAME COLUMN PROCESSED_AT TO STATE_CHANGED_AT;
