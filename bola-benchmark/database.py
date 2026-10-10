"""PostgreSQL for deployments, SQLite for local development and isolated tests."""
import atexit
import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from threading import RLock
from itertools import count

DATABASE_URL = os.environ.get("DATABASE_URL", "")
DATABASE_BACKEND = "PostgreSQL" if DATABASE_URL.startswith(("postgresql://", "postgres://")) else "SQLite"


class SQLiteCursorWrapper:
    def __init__(self, cursor):
        self.cur = cursor

    def _transform_sql(self, sql):
        sql = sql.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
        sql = sql.replace("DOUBLE PRECISION", "REAL").replace("BOOLEAN", "INTEGER")
        sql = re.sub(r"\bNOW\(\)", "CURRENT_TIMESTAMP", sql, flags=re.I)
        sql = sql.replace("TEXT[]", "TEXT")
        sql = re.sub(r"SELECT ctid\b", "SELECT rowid AS ctid", sql, flags=re.I)
        sql = re.sub(r"WHERE ctid\b", "WHERE rowid", sql, flags=re.I)
        return sql.replace("%s", "?")

    def execute(self, sql, params=None):
        sql = self._transform_sql(sql)
        if params is not None:
            self.cur.execute(sql, params)
        else:
            # executescript() commits implicitly, which breaks migration rollback.
            statement = ""
            for char in sql:
                statement += char
                if char == ";" and sqlite3.complete_statement(statement):
                    self.cur.execute(statement)
                    statement = ""
            if statement.strip():
                self.cur.execute(statement)
        return self

    def executemany(self, sql, params):
        self.cur.executemany(self._transform_sql(sql), params)
        return self

    def fetchone(self):
        row = self.cur.fetchone()
        return dict(row) if row is not None else None

    def fetchall(self):
        return [dict(row) for row in self.cur.fetchall()]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.cur.close()


class SQLiteConnWrapper:
    def __init__(self, conn):
        self.conn = conn

    def cursor(self):
        return SQLiteCursorWrapper(self.conn.cursor())

    def execute(self, sql, params=None):
        return self.cursor().execute(sql, params)

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()


if DATABASE_BACKEND == "PostgreSQL":
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool

    _pool = ConnectionPool(
        DATABASE_URL,
        min_size=1,
        max_size=int(os.environ.get("DB_POOL_MAX_SIZE", "10")),
        timeout=float(os.environ.get("DB_POOL_TIMEOUT_SECONDS", "5")),
        open=True,
        kwargs={"row_factory": dict_row, "connect_timeout": 5},
    )
    atexit.register(_pool.close)

    @contextmanager
    def db():
        with _pool.connection() as conn:
            yield conn
else:
    if DATABASE_URL and not DATABASE_URL.startswith("sqlite:///"):
        raise RuntimeError("DATABASE_URL must use postgresql://, postgres:// or sqlite:///")
    if os.environ.get("APP_ENV") == "prod":
        raise RuntimeError("APP_ENV=prod requires a PostgreSQL DATABASE_URL")
    filename = DATABASE_URL.removeprefix("sqlite:///") if DATABASE_URL else str(Path(__file__).with_name("bola.db"))
    _connection = sqlite3.connect(filename, check_same_thread=False)
    _connection.row_factory = sqlite3.Row
    _connection.execute("PRAGMA journal_mode=WAL")
    _connection.execute("PRAGMA busy_timeout=5000")
    _lock = RLock()
    _wrapper = SQLiteConnWrapper(_connection)
    _savepoints = count()
    atexit.register(_connection.close)

    @contextmanager
    def db():
        with _lock:
            savepoint = f"cyberaccess_{next(_savepoints)}"
            _connection.execute(f"SAVEPOINT {savepoint}")
            try:
                yield _wrapper
                _connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            except Exception:
                _connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                _connection.execute(f"RELEASE SAVEPOINT {savepoint}")
                raise


def has_column(connection, table, column):
    if DATABASE_BACKEND == "PostgreSQL":
        return bool(connection.execute(
            "SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() "
            "AND table_name = %s AND column_name = %s", (table, column)
        ).fetchone())
    return any(row["name"] == column for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall())
