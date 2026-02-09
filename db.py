import os
import psycopg
from psycopg.rows import dict_row

DB_URL = os.getenv("DATABASE_URL")

def db():
    if not DB_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg.connect(DB_URL, row_factory=dict_row)

def q1(sql, params=()):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()

def q(sql, params=()):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()

def exec_sql(sql, params=()):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            conn.commit()
