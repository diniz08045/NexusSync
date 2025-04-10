"""
SQL injection protection module.

This module provides utilities to prevent SQL injection attacks, validate SQL inputs,
and safely execute queries against the database.
"""

import re
import logging
from typing import Any, List, Dict, Tuple, Optional, Union

from sqlalchemy.engine import Engine
from sqlalchemy.sql import text
from sqlalchemy.orm import Session
from flask import abort, current_app, g

# Setup SQL protection logger
sql_logger = logging.getLogger("app.sql_protection")
sql_logger.setLevel(logging.INFO)

# Regex patterns for detecting SQL injection attempts
SQL_INJECTION_PATTERNS = [
    # Basic SQL commands
    r'(?i)\bSELECT\b.+\bFROM\b',
    r'(?i)\bINSERT\b.+\bINTO\b',
    r'(?i)\bUPDATE\b.+\bSET\b',
    r'(?i)\bDELETE\b.+\bFROM\b',
    r'(?i)\bDROP\b.+\bTABLE\b',
    r'(?i)\bALTER\b.+\bTABLE\b',
    r'(?i)\bEXEC\b.+\bsp_',
    r'(?i)\bCREATE\b.+\bTABLE\b',
    
    # SQL operators and conditions
    r'(?i)\bUNION\b.+\bSELECT\b',
    r'(?i)\bAND\b.+\b(1|true)\b',
    r'(?i)\bOR\b.+\b(1|true)\b',
    
    # SQL comments
    r'--',
    r'/\*.*\*/',
    
    # String concatenation
    r'\|\|',
    r'\+\+',
    
    # Batched queries
    r';.+(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)',
]

def is_sql_injection_attempt(value: str) -> bool:
    """
    Check if a string contains potential SQL injection.
    
    Args:
        value: The string to check
        
    Returns:
        bool: True if SQL injection is detected, False otherwise
    """
    if not isinstance(value, str):
        return False
        
    # Check against SQL injection patterns
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, value):
            sql_logger.warning(f"Potential SQL injection detected: {value}")
            return True
            
    return False

def sanitize_sql_input(value: str) -> str:
    """
    Sanitize input for SQL queries (basic sanitization only).
    
    Note: This is a basic approach. For proper SQL safety, always use
    parameterized queries or an ORM like SQLAlchemy.
    
    Args:
        value: The value to sanitize
        
    Returns:
        str: The sanitized value
    """
    if not isinstance(value, str):
        return str(value)
        
    # Remove common SQL injection patterns
    sanitized = value
    
    # Replace quotes (very basic approach)
    sanitized = sanitized.replace("'", "''")
    
    # Replace SQL comment markers
    sanitized = sanitized.replace("--", "")
    sanitized = re.sub(r'/\*.*?\*/', '', sanitized)
    
    # Replace semicolons to prevent multiple statements
    sanitized = sanitized.replace(";", "")
    
    return sanitized

def validate_table_name(table_name: str) -> bool:
    """
    Validate if a table name contains only allowed characters.
    
    Args:
        table_name: The table name to validate
        
    Returns:
        bool: True if the table name is valid, False otherwise
    """
    # Only allow alphanumeric characters and underscores in table names
    return bool(re.match(r'^[a-zA-Z0-9_]+$', table_name))

def validate_column_name(column_name: str) -> bool:
    """
    Validate if a column name contains only allowed characters.
    
    Args:
        column_name: The column name to validate
        
    Returns:
        bool: True if the column name is valid, False otherwise
    """
    # Only allow alphanumeric characters and underscores in column names
    return bool(re.match(r'^[a-zA-Z0-9_]+$', column_name))

def validate_order_direction(direction: str) -> bool:
    """
    Validate if an ORDER BY direction is valid.
    
    Args:
        direction: The direction to validate
        
    Returns:
        bool: True if the direction is valid, False otherwise
    """
    return direction.upper() in ('ASC', 'DESC')

def safe_order_by(column: str, direction: str = 'ASC', 
                  allowed_columns: List[str] = None) -> Optional[str]:
    """
    Create a safe ORDER BY clause.
    
    Args:
        column: The column to order by
        direction: The direction (ASC or DESC)
        allowed_columns: List of allowed columns for ordering
        
    Returns:
        Optional[str]: The safe ORDER BY clause, or None if invalid
    """
    # Validate direction
    if not validate_order_direction(direction):
        sql_logger.warning(f"Invalid ORDER BY direction: {direction}")
        return None
        
    # Validate column against allowed list
    if allowed_columns and column not in allowed_columns:
        sql_logger.warning(f"Order by column not in allowed list: {column}")
        return None
        
    # Validate column name format
    if not validate_column_name(column):
        sql_logger.warning(f"Invalid column name format: {column}")
        return None
        
    # Return safe ORDER BY clause
    return f"{column} {direction}"

def safe_like_pattern(pattern: str) -> str:
    """
    Create a safe LIKE pattern, escaping special characters.
    
    Args:
        pattern: The LIKE pattern to sanitize
        
    Returns:
        str: The sanitized LIKE pattern
    """
    # Escape special LIKE pattern characters
    if not isinstance(pattern, str):
        pattern = str(pattern)
        
    # Escape LIKE special characters: % and _
    pattern = pattern.replace('%', r'\%').replace('_', r'\_')
    
    # Add the wildcards back for searching
    return f"%{pattern}%"

def safe_limit_offset(limit: int, offset: int) -> Tuple[int, int]:
    """
    Ensure LIMIT and OFFSET values are safe.
    
    Args:
        limit: The LIMIT value
        offset: The OFFSET value
        
    Returns:
        Tuple[int, int]: Safe (limit, offset) values
    """
    try:
        # Ensure values are integers and within reasonable ranges
        limit = int(limit)
        offset = int(offset)
        
        # Apply reasonable limits
        max_limit = 1000
        max_offset = 10000
        
        if limit <= 0 or limit > max_limit:
            sql_logger.warning(f"Invalid LIMIT value: {limit}, using default")
            limit = 50
            
        if offset < 0 or offset > max_offset:
            sql_logger.warning(f"Invalid OFFSET value: {offset}, using default")
            offset = 0
            
        return limit, offset
    except (ValueError, TypeError):
        sql_logger.warning(f"Invalid LIMIT/OFFSET values: limit={limit}, offset={offset}")
        return 50, 0

def log_query(query: str, parameters: Dict[str, Any] = None) -> None:
    """
    Log a SQL query for security auditing.
    
    Args:
        query: The SQL query string
        parameters: Query parameters
    """
    # In production, you might want to sanitize sensitive data before logging
    sql_logger.info(f"SQL Query: {query}")
    if parameters:
        sql_logger.info(f"Parameters: {parameters}")

def safe_execute_query(
    session: Session, 
    query: str, 
    parameters: Dict[str, Any] = None
) -> List[Dict[str, Any]]:
    """
    Safely execute a SQL query with parameterized values.
    
    Args:
        session: SQLAlchemy session
        query: SQL query string
        parameters: Query parameters
        
    Returns:
        List[Dict[str, Any]]: Query results as dictionaries
    """
    try:
        # Log the query for auditing
        log_query(query, parameters)
        
        # Execute the query with parameters
        result = session.execute(text(query), parameters or {})
        
        # Convert result to list of dictionaries
        column_names = result.keys()
        rows = [dict(zip(column_names, row)) for row in result.fetchall()]
        
        return rows
    except Exception as e:
        sql_logger.error(f"Error executing query: {str(e)}")
        # In production, you might want to handle this differently
        raise

def safe_execute_with_result(
    engine: Engine, 
    query: str, 
    parameters: Dict[str, Any] = None
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Execute a query safely and return results with column names.
    
    Args:
        engine: SQLAlchemy engine
        query: SQL query string
        parameters: Query parameters
        
    Returns:
        Tuple[List[Dict[str, Any]], List[str]]: Query results and column names
    """
    try:
        # Log the query for auditing
        log_query(query, parameters)
        
        # Execute the query
        with engine.connect() as connection:
            result = connection.execute(text(query), parameters or {})
            
            # Get column names
            column_names = result.keys()
            
            # Get row data
            rows = [dict(zip(column_names, row)) for row in result.fetchall()]
            
            return rows, list(column_names)
    except Exception as e:
        sql_logger.error(f"Error executing query: {str(e)}")
        # In production, you might want to handle this differently
        raise

def build_safe_where_clause(
    conditions: Dict[str, Any], 
    allowed_columns: List[str] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Build a safe WHERE clause from a dictionary of conditions.
    
    Args:
        conditions: Dictionary mapping column names to values
        allowed_columns: List of allowed column names
        
    Returns:
        Tuple[str, Dict[str, Any]]: WHERE clause and parameters
    """
    where_clauses = []
    parameters = {}
    
    for idx, (column, value) in enumerate(conditions.items()):
        # Validate column name
        if not validate_column_name(column):
            sql_logger.warning(f"Invalid column name in WHERE clause: {column}")
            continue
            
        # Check if column is in allowed list
        if allowed_columns and column not in allowed_columns:
            sql_logger.warning(f"Column not in allowed list: {column}")
            continue
            
        # Create parameter name (avoid collisions)
        param_name = f"param_{idx}"
        
        # Add to clauses and parameters
        where_clauses.append(f"{column} = :{param_name}")
        parameters[param_name] = value
        
    # Build the WHERE clause
    if where_clauses:
        where_sql = " AND ".join(where_clauses)
        return where_sql, parameters
    else:
        return "1=1", {}  # Default to always true if no valid conditions

def build_safe_query(
    table: str,
    columns: List[str] = None,
    where_conditions: Dict[str, Any] = None,
    order_by: str = None,
    order_direction: str = 'ASC',
    limit: int = 50,
    offset: int = 0,
    allowed_columns: List[str] = None,
    allowed_tables: List[str] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Build a safe SQL query from components.
    
    Args:
        table: Table name
        columns: Columns to select
        where_conditions: WHERE conditions
        order_by: Column to order by
        order_direction: Order direction (ASC/DESC)
        limit: LIMIT value
        offset: OFFSET value
        allowed_columns: List of allowed column names
        allowed_tables: List of allowed table names
        
    Returns:
        Tuple[str, Dict[str, Any]]: SQL query and parameters
    """
    # Validate table name
    if not validate_table_name(table):
        sql_logger.error(f"Invalid table name: {table}")
        abort(400, "Invalid query parameters")
        
    # Check if table is in allowed list
    if allowed_tables and table not in allowed_tables:
        sql_logger.error(f"Table not in allowed list: {table}")
        abort(400, "Invalid query parameters")
        
    # Validate columns
    safe_columns = []
    if columns:
        for col in columns:
            if not validate_column_name(col):
                sql_logger.warning(f"Invalid column name: {col}")
                continue
                
            if allowed_columns and col not in allowed_columns:
                sql_logger.warning(f"Column not in allowed list: {col}")
                continue
                
            safe_columns.append(col)
    
    # Use all columns if none specified or all invalid
    column_str = ", ".join(safe_columns) if safe_columns else "*"
    
    # Build the base query
    query = f"SELECT {column_str} FROM {table}"
    
    # Add WHERE clause if conditions provided
    parameters = {}
    if where_conditions:
        where_sql, where_params = build_safe_where_clause(
            where_conditions, allowed_columns
        )
        if where_sql:
            query += f" WHERE {where_sql}"
            parameters.update(where_params)
            
    # Add ORDER BY if provided
    if order_by:
        order_clause = safe_order_by(order_by, order_direction, allowed_columns)
        if order_clause:
            query += f" ORDER BY {order_clause}"
            
    # Add LIMIT and OFFSET
    safe_limit, safe_offset = safe_limit_offset(limit, offset)
    query += f" LIMIT {safe_limit} OFFSET {safe_offset}"
    
    return query, parameters