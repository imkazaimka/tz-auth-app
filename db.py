import sqlite3
from contextlib import contextmanager

DB_PATH = "auth.db"


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with open("models.sql", "r", encoding="utf-8") as f:
        schema = f.read()

    with get_conn() as conn:
        conn.executescript(schema)
