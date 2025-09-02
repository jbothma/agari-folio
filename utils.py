"""
Utility functions for Folio API

This module contains common utility functions used throughout the application.
"""

import logging
import os
import psycopg2
from datetime import datetime, date
from decimal import Decimal

logger = logging.getLogger(__name__)


def get_db_connection():
    """Get database connection using environment variables"""
    try:
        conn = psycopg2.connect(
            host=os.getenv('FOLIO_DB_HOST', 'folio-db'),
            port=os.getenv('FOLIO_DB_PORT', '5432'),
            database=os.getenv('FOLIO_DB_NAME', 'folio'),
            user=os.getenv('FOLIO_DB_USER', 'folio'),
            password=os.getenv('FOLIO_DB_PASSWORD', 'folio'),
            connect_timeout=10
        )
        return conn
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        raise


def serialize_record(record):
    """Convert a database record to a JSON-serializable dictionary"""
    if not record:
        return None
    
    # Convert psycopg2.extras.RealDictRow to regular dict
    if hasattr(record, '_asdict'):
        data = record._asdict()
    elif hasattr(record, 'items'):
        data = dict(record.items())
    else:
        data = dict(record)
    
    # Convert non-serializable types
    for key, value in data.items():
        if isinstance(value, datetime):
            data[key] = value.isoformat()
        elif isinstance(value, date):
            data[key] = value.isoformat()
        elif isinstance(value, Decimal):
            data[key] = float(value)
    
    return data
