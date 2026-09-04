import logging
import os
from typing import Optional

import psycopg2
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


def get_connection():
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        return psycopg2.connect(database_url)

    return psycopg2.connect(
        user=os.getenv("SUPABASE_DB_USER") or os.getenv("user") or "postgres",
        password=os.getenv("SUPABASE_PASSWORD"),
        host=os.getenv("SUPABASE_DB_HOST", "aws-1-ap-southeast-1.pooler.supabase.com"),
        port=os.getenv("SUPABASE_DB_PORT", "6543"),
        database=os.getenv("SUPABASE_DB_NAME", "postgres"),
        sslmode="require",
    )


def execute(sql: str, params: Optional[tuple] = None) -> None:
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(sql, params)
        conn.commit()
    except Exception:
        if conn:
            conn.rollback()
        logger.exception("execute failed (%s)", sql[:120])
        raise
    finally:
        if conn:
            conn.close()


def execute_many(sql: str, rows: list[tuple]) -> None:
    if not rows:
        return
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.executemany(sql, rows)
        conn.commit()
    except Exception:
        if conn:
            conn.rollback()
        logger.exception("execute_many failed (%s)", sql[:120])
        raise
    finally:
        if conn:
            conn.close()


def querydb(query: str, params=None):
    conn = None

    try:
        conn = get_connection()

        with conn.cursor() as cursor:
            cursor.execute(query, params)

            if cursor.description is not None:
                return cursor.fetchall()

            conn.commit()
            return "Query executed successfully"

    except Exception:
        if conn:
            conn.rollback()
        logger.exception("Database query failed")
        raise

    finally:
        if conn:
            conn.close()


def querydb_dicts(query: str, params=None) -> list[dict]:
    """Giống querydb nhưng trả list[dict] với key là tên cột."""
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            if cursor.description is None:
                conn.commit()
                return []
            cols = [desc[0] for desc in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    except Exception:
        if conn:
            conn.rollback()
        logger.exception("querydb_dicts failed (%s)", query[:120])
        raise
    finally:
        if conn:
            conn.close()


def querydb_dicts_dsn(dsn: str, query: str, params=None) -> list[dict]:
    """Run a read query against a one-off PostgreSQL DSN and return dict rows."""
    conn = None
    try:
        conn = psycopg2.connect(dsn)
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            if cursor.description is None:
                conn.commit()
                return []
            cols = [desc[0] for desc in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    except Exception:
        if conn:
            conn.rollback()
        logger.exception("querydb_dicts_dsn failed (%s)", query[:120])
        raise
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    result = querydb("SELECT * FROM users")
    print(result)
