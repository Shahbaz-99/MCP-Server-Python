"""SQL read-only guard (layer 1 of 2). Layer 2 is a read-only database session.

The guard parses with sqlglot, walks the WHOLE tree (not just the root), and returns SQL
regenerated from the analysed tree. Executing the regenerated text, not the caller's text,
removes parser/database disagreements as a bypass route.
"""

from __future__ import annotations

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

from mcp_hub.errors import AccessDenied, ValidationFailed

MAX_QUERY_CHARS = 10_000

_FORBIDDEN_NODES: tuple[type[exp.Expression], ...] = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Merge,
    exp.Create,
    exp.Drop,
    exp.Alter,
    exp.Command,
    exp.Into,
    exp.Lock,
    exp.Pragma,
    exp.Attach,
    exp.Detach,
    exp.Copy,
    exp.Set,
    exp.Use,
    exp.TruncateTable,
    exp.Transaction,
    exp.Commit,
    exp.Rollback,
    exp.Grant,
    exp.Revoke,
)

_FORBIDDEN_FUNCTIONS = frozenset(
    {
        "nextval",
        "setval",
        "set_config",
        "load_extension",
        "readfile",
        "writefile",
        "edit",
        "dblink",
        "dblink_exec",
        "query_to_xml",
        "query_to_xml_and_xmlschema",
        "query_to_xmlschema",
        "cursor_to_xml",
        "cursor_to_xmlschema",
        "table_to_xml",
        "table_to_xml_and_xmlschema",
        "schema_to_xml",
        "database_to_xml",
    }
)
_FORBIDDEN_FUNCTION_PREFIXES = ("pg_", "lo_", "dblink", "txid_")

DIALECTS = {"sqlite": "sqlite", "postgres": "postgres"}


def _function_name(node: exp.Func) -> str:
    name = node.name if isinstance(node, exp.Anonymous) else node.sql_name()
    return str(name).lower()


def validate_select(sql: str, dialect: str) -> str:
    """Return the vetted, regenerated SQL, or raise. Only a single SELECT-type query is allowed."""
    if dialect not in DIALECTS:
        raise ValidationFailed(f"Unsupported SQL dialect: {dialect}")
    if not sql or not sql.strip():
        raise ValidationFailed("Query is empty.")
    if len(sql) > MAX_QUERY_CHARS:
        raise ValidationFailed(f"Query longer than {MAX_QUERY_CHARS} characters.")
    if "\x00" in sql:
        raise ValidationFailed("Query contains a NUL byte.")
    try:
        trees = [t for t in sqlglot.parse(sql, read=DIALECTS[dialect]) if t is not None]
    except SqlglotError:
        raise ValidationFailed("Query could not be parsed.") from None
    if len(trees) != 1:
        raise AccessDenied("Exactly one statement is allowed.")
    root = trees[0]
    if not isinstance(root, exp.Select | exp.SetOperation):
        raise AccessDenied("Only SELECT queries are allowed.")
    for node in root.walk():
        if isinstance(node, _FORBIDDEN_NODES):
            raise AccessDenied(f"{type(node).__name__} is not allowed in a read-only query.")
        if isinstance(node, exp.Func):
            name = _function_name(node)
            if name in _FORBIDDEN_FUNCTIONS or name.startswith(_FORBIDDEN_FUNCTION_PREFIXES):
                raise AccessDenied(f"Function '{name}' is not allowed.")
    return root.sql(dialect=DIALECTS[dialect], comments=False)
