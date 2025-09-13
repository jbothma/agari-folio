"""
Database connection and configuration for AGARI Folio
"""
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)

# Database configuration from environment variables
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'postgres.local'),
    'port': os.getenv('DB_PORT', '5432'),
    'database': os.getenv('DB_NAME', 'folio'),
    'user': os.getenv('DB_USER', 'folio'),
    'password': os.getenv('DB_PASSWORD', 'folio_password')
}

def get_db_connection():
    """Get a database connection"""
    try:
        connection = psycopg2.connect(
            host=DB_CONFIG['host'],
            port=DB_CONFIG['port'],
            database=DB_CONFIG['database'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            cursor_factory=RealDictCursor
        )
        return connection
    except psycopg2.Error as e:
        logger.error(f"Database connection error: {e}")
        raise

@contextmanager
def get_db_cursor():
    """Context manager for database operations"""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        yield cursor
        connection.commit()
    except Exception as e:
        if connection:
            connection.rollback()
        logger.error(f"Database operation error: {e}")
        raise
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

def init_database():
    """Initialize the database with tables and schemas"""
    try:
        # Check if tables already exist
        with get_db_cursor() as cursor:
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name IN ('pathogens', 'projects', 'studies')
            """)
            existing_tables = [row['table_name'] for row in cursor.fetchall()]
            
            if len(existing_tables) == 3:
                logger.info("Database already initialized - all tables exist")
                return
            elif len(existing_tables) > 0:
                logger.info(f"Database partially initialized - found tables: {existing_tables}")
            else:
                logger.info("Database not initialized - creating tables")
        
        # Read the init.sql file (it's in the same directory as this file)
        init_sql_path = os.path.join(os.path.dirname(__file__), 'init.sql')
        with open(init_sql_path, 'r') as f:
            init_sql = f.read()
        
        # Execute the initialization script
        with get_db_cursor() as cursor:
            cursor.execute(init_sql)
            logger.info("Database initialization completed successfully")
            
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        raise

def check_db_connection():
    """Check if database connection is working"""
    try:
        with get_db_cursor() as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            return result is not None
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")
        return False
