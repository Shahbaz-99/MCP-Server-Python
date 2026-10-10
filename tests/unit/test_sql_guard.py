"""Adversarial tests for the SQL read-only guard (layer 1)."""

from __future__ import annotations

import pytest

from mcp_hub.errors import AccessDenied, HubError, ValidationFailed
from mcp_hub.plugins.sql.guard import MAX_QUERY_CHARS, validate_select

ALLOWED = [
    ("sqlite", "SELECT 1"),
    ("sqlite", "select * from t where a = ? and b > ?"),
    ("postgres", "SELECT * FROM t WHERE a = $1"),
    ("sqlite", "WITH c AS (SELECT 1 AS x) SELECT * FROM c UNION SELECT 2"),
    ("sqlite", "SELECT a, count(*) FROM t GROUP BY a HAVING count(*) > 1 ORDER BY 2 LIMIT 5"),
    ("sqlite", "SELECT * FROM t1 JOIN t2 ON t1.id = t2.id WHERE t1.x IN (SELECT y FROM t3)"),
    ("postgres", "SELECT now(), version(), current_setting('server_version')"),
    ("sqlite", "SELECT * FROM pragma_table_info('t')"),
    ("sqlite", "SELECT 1 /* a harmless comment */"),
]


@pytest.mark.parametrize(("dialect", "sql"), ALLOWED)
def test_allowed(dialect: str, sql: str) -> None:
    out = validate_select(sql, dialect)
    assert out.upper().startswith(("SELECT", "WITH"))


DENIED = [
    # stacked statements, including ones hidden after comments or semicolons
    ("sqlite", "SELECT 1; DROP TABLE t"),
    ("sqlite", "SELECT 1; SELECT 2"),
    ("postgres", "SELECT 1;DELETE FROM t"),
    ("sqlite", "SELECT 1 /* x */; /* y */ DELETE FROM t"),
    # writes and DDL
    ("sqlite", "INSERT INTO t VALUES (1)"),
    ("sqlite", "UPDATE t SET a = 1"),
    ("sqlite", "DELETE FROM t"),
    ("sqlite", "REPLACE INTO t VALUES (1)"),
    ("sqlite", "CREATE TABLE x (a int)"),
    ("sqlite", "DROP TABLE t"),
    ("sqlite", "ALTER TABLE t ADD COLUMN c int"),
    ("sqlite", "TRUNCATE TABLE t"),
    ("postgres", "TRUNCATE t"),
    ("sqlite", "VACUUM"),
    ("sqlite", "VACUUM INTO 'copy.db'"),
    # engine control
    ("sqlite", "ATTACH DATABASE 'other.db' AS o"),
    ("sqlite", "DETACH DATABASE o"),
    ("sqlite", "PRAGMA writable_schema = 1"),
    ("sqlite", "PRAGMA query_only = OFF"),
    ("postgres", "SET ROLE admin"),
    ("postgres", "SET default_transaction_read_only = off"),
    ("postgres", "BEGIN"),
    ("postgres", "COMMIT"),
    ("postgres", "COPY t TO PROGRAM 'id'"),
    ("postgres", "COPY t FROM '/etc/passwd'"),
    ("postgres", "DO $$ BEGIN DELETE FROM t; END $$"),
    ("postgres", "CALL p()"),
    ("postgres", "GRANT ALL ON t TO public"),
    ("postgres", "EXPLAIN ANALYZE DELETE FROM t"),
    ("postgres", "EXPLAIN SELECT 1"),
    # writes smuggled under a SELECT root
    ("postgres", "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d"),
    ("postgres", "WITH i AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM i"),
    ("postgres", "WITH u AS (UPDATE t SET a = 1 RETURNING *) SELECT * FROM u"),
    ("postgres", "SELECT * INTO newtable FROM t"),
    ("postgres", "SELECT * FROM t FOR UPDATE"),
    ("postgres", "SELECT * FROM t FOR SHARE"),
    (
        "sqlite",
        "SELECT * FROM (SELECT 1) WHERE 1 IN "
        "(WITH d AS (DELETE FROM t RETURNING 1) SELECT 1 FROM d)",
    ),
    # dangerous functions (case and quoting variants)
    ("postgres", "SELECT nextval('s')"),
    ("postgres", "SELECT NEXTVAL('s')"),
    ("postgres", "SELECT setval('s', 1)"),
    ("postgres", "SELECT pg_read_file('/etc/passwd')"),
    ("postgres", "SELECT pg_sleep(100)"),
    ("postgres", "SELECT pg_terminate_backend(1)"),
    ("postgres", "SELECT lo_import('/etc/passwd')"),
    ("postgres", "SELECT set_config('default_transaction_read_only', 'off', false)"),
    ("postgres", "SELECT query_to_xml('delete from t', true, true, '')"),
    ("postgres", "SELECT dblink('host=x', 'select 1')"),
    ("sqlite", "SELECT load_extension('evil.dll')"),
    ("sqlite", "SELECT readfile('/etc/passwd')"),
    ("sqlite", "SELECT writefile('x', 'y')"),
    ("sqlite", "SELECT * FROM t WHERE a = (SELECT load_extension('x'))"),
]


@pytest.mark.parametrize(("dialect", "sql"), DENIED)
def test_denied(dialect: str, sql: str) -> None:
    with pytest.raises(HubError):
        validate_select(sql, dialect)


def test_denials_use_access_denied_not_just_parse_errors() -> None:
    for sql in ("DROP TABLE t", "SELECT 1; SELECT 2", "SELECT load_extension('x')"):
        with pytest.raises(AccessDenied):
            validate_select(sql, "sqlite")


@pytest.mark.parametrize("sql", ["", "   ", ";", "\n\t"])
def test_empty_rejected(sql: str) -> None:
    with pytest.raises(HubError):
        validate_select(sql, "sqlite")


def test_limits_and_garbage() -> None:
    with pytest.raises(ValidationFailed, match="longer"):
        validate_select("SELECT '" + "a" * MAX_QUERY_CHARS + "'", "sqlite")
    with pytest.raises(ValidationFailed, match="NUL"):
        validate_select("SELECT 1\x00; DROP TABLE t", "sqlite")
    with pytest.raises(HubError):
        validate_select("SELEC T FROM FROM ((", "sqlite")
    with pytest.raises(ValidationFailed, match="dialect"):
        validate_select("SELECT 1", "oracle")


def test_executes_regenerated_sql_without_comments() -> None:
    out = validate_select("SELECT 1 -- ; DROP TABLE t", "sqlite")
    assert "DROP" not in out and ";" not in out
    out = validate_select("SELECT /* hidden */ a FROM t", "postgres")
    assert "hidden" not in out
