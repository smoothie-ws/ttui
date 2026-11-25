"""Persistent limits for administrator sign-in."""
import sqlite3
import time
from contextlib import closing

WINDOW = 60
LIMIT = 10


def reserve_attempt(database, address, now=None):
    now = int(time.time()) if now is None else now
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
            address TEXT NOT NULL, started INTEGER NOT NULL, attempts INTEGER NOT NULL,
            PRIMARY KEY (address)
        )""")
        connection.execute("DELETE FROM login_attempts WHERE started <= ?", (now - WINDOW,))
        row = connection.execute(
            "SELECT started, attempts FROM login_attempts WHERE address = ?", (address,)
        ).fetchone()
        if row and row[1] >= LIMIT:
            return max(1, min(WINDOW, row[0] + WINDOW - now))
        connection.execute("""INSERT INTO login_attempts VALUES (?, ?, 1)
            ON CONFLICT(address) DO UPDATE SET attempts = attempts + 1""", (address, now))
        return 0


def clear_attempts(database, address):
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("DELETE FROM login_attempts WHERE address = ?", (address,))
