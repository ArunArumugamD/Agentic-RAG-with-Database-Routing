"""
Advanced logging configuration for the Agentic RAG system.
Production-ready logging with structured output and multiple handlers.
"""

import logging
import logging.config
import sys
from typing import Dict, Any
from pathlib import Path
import json
from datetime import datetime

from config.settings import settings


class JSONFormatter(logging.Formatter):
    """
    Custom JSON formatter for structured logging.
    Outputs logs in JSON format for better parsing and analysis.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        # Create base log entry
        log_entry = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add exception information if present
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": self.formatException(record.exc_info)
            }
        
        # Add extra fields from record
        extra_fields = {
            k: v for k, v in record.__dict__.items()
            if k not in {
                'name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                'filename', 'module', 'exc_info', 'exc_text', 'stack_info',
                'lineno', 'funcName', 'created', 'msecs', 'relativeCreated',
                'thread', 'threadName', 'processName', 'process', 'getMessage'
            }
        }
        
        if extra_fields:
            log_entry["extra"] = extra_fields
        
        return json.dumps(log_entry, default=str)


class CybersecurityLogFilter(logging.Filter):
    """
    Custom filter for cybersecurity-specific log processing.
    Adds context and sanitizes sensitive information.
    """
    
    SENSITIVE_PATTERNS = [
        "password", "token", "key", "secret", "credential"
    ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        # Add cybersecurity context
        record.service = "agentic-rag"
        record.environment = 'development' if settings.DEBUG else 'production'
        
        # Sanitize sensitive information in log messages
        message = record.getMessage()
        for pattern in self.SENSITIVE_PATTERNS:
            if pattern in message.lower():
                # Replace potential sensitive data with placeholder
                record.msg = record.msg.replace(
                    message.split(pattern)[1].split()[0] if pattern in message.lower() else "",
                    "****"
                )
        
        # Add threat intelligence context if available
        if hasattr(record, 'query_type'):
            record.intelligence_type = getattr(record, 'query_type', 'unknown')
        
        return True


def setup_logging() -> None:
    """
    Setup comprehensive logging configuration for the application.
    Configures multiple handlers and formatters based on environment.
    """
    
    # Ensure logs directory exists
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Define logging configuration
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S"
            },
            "detailed": {
                "format": "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d - %(funcName)s(): %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S"
            },
            "json": {
                "()": JSONFormatter
            }
        },
        "filters": {
            "cybersecurity_filter": {
                "()": CybersecurityLogFilter
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": "INFO" if not settings.DEBUG else "DEBUG",
                "formatter": "standard",
                "stream": sys.stdout,
                "filters": ["cybersecurity_filter"]
            },
            "file_general": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "INFO",
                "formatter": "detailed",
                "filename": "logs/agentic_rag.log",
                "maxBytes": 50 * 1024 * 1024,  # 50MB
                "backupCount": 10,
                "filters": ["cybersecurity_filter"]
            },
            "file_json": {
                "class": "logging.handlers.RotatingFileHandler", 
                "level": "INFO",
                "formatter": "json",
                "filename": "logs/agentic_rag.json",
                "maxBytes": 100 * 1024 * 1024,  # 100MB
                "backupCount": 5,
                "filters": ["cybersecurity_filter"]
            },
            "file_error": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "ERROR",
                "formatter": "detailed",
                "filename": "logs/errors.log", 
                "maxBytes": 10 * 1024 * 1024,  # 10MB
                "backupCount": 20,
                "filters": ["cybersecurity_filter"]
            },
            "file_security": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "WARNING",
                "formatter": "json",
                "filename": "logs/security.log",
                "maxBytes": 20 * 1024 * 1024,  # 20MB
                "backupCount": 30,
                "filters": ["cybersecurity_filter"]
            }
        },
        "loggers": {
            "": {  # Root logger
                "level": settings.LOG_LEVEL,
                "handlers": ["console", "file_general", "file_json", "file_error"]
            },
            "src.routing": {
                "level": "DEBUG" if settings.DEBUG else "INFO",
                "handlers": ["console", "file_general"],
                "propagate": False
            },
            "src.agents": {
                "level": "DEBUG" if settings.DEBUG else "INFO", 
                "handlers": ["console", "file_general"],
                "propagate": False
            },
            "src.database": {
                "level": "INFO",
                "handlers": ["console", "file_general"],
                "propagate": False
            },
            "src.api": {
                "level": "INFO",
                "handlers": ["console", "file_general"],
                "propagate": False
            },
            "security": {
                "level": "WARNING",
                "handlers": ["console", "file_security", "file_error"],
                "propagate": False
            },
            "uvicorn": {
                "level": "INFO",
                "handlers": ["console", "file_general"],
                "propagate": False
            },
            "sqlalchemy": {
                "level": "WARNING",
                "handlers": ["file_general"],
                "propagate": False
            }
        }
    }
    
    # Apply logging configuration
    logging.config.dictConfig(logging_config)
    
    # Set specific log levels for third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("langchain").setLevel(logging.INFO)
    
    # Create security logger for sensitive operations
    security_logger = logging.getLogger("security")
    security_logger.info("Logging system initialized", extra={
        "environment": 'development' if settings.DEBUG else 'production',
        "debug_mode": settings.DEBUG,
        "log_level": settings.LOG_LEVEL
    })


def get_logger(name: str) -> logging.Logger:
    """
    Get a configured logger instance.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)


def log_security_event(event_type: str, details: Dict[str, Any], level: str = "WARNING"):
    """
    Log security-related events with structured format.
    
    Args:
        event_type: Type of security event
        details: Event details dictionary
        level: Log level (WARNING, ERROR, CRITICAL)
    """
    security_logger = logging.getLogger("security")
    log_method = getattr(security_logger, level.lower())
    
    log_method(f"Security Event: {event_type}", extra={
        "event_type": event_type,
        "details": details,
        "timestamp": datetime.utcnow().isoformat(),
        "service": "agentic-rag"
    })


def log_threat_intelligence_event(
    query: str,
    result_count: int,
    confidence: float,
    processing_time: float,
    agent_used: str,
    success: bool
):
    """
    Log threat intelligence query events for analysis and monitoring.
    
    Args:
        query: User query
        result_count: Number of results returned
        confidence: Confidence score
        processing_time: Time taken to process
        agent_used: Agent that processed the query
        success: Whether processing was successful
    """
    intelligence_logger = logging.getLogger("src.agents")
    
    intelligence_logger.info("Threat Intelligence Query Processed", extra={
        "query_hash": hash(query) % 1000000,  # Hash query for privacy
        "query_length": len(query),
        "result_count": result_count,
        "confidence": confidence,
        "processing_time": processing_time,
        "agent_used": agent_used,
        "success": success,
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": "intelligence_query"
    })


def log_database_operation(
    operation: str,
    table: str,
    duration: float,
    success: bool,
    record_count: int = None,
    error: str = None
):
    """
    Log database operations for performance monitoring.
    
    Args:
        operation: Type of operation (SELECT, INSERT, UPDATE, etc.)
        table: Database table involved
        duration: Operation duration in seconds
        success: Whether operation succeeded
        record_count: Number of records affected
        error: Error message if failed
    """
    db_logger = logging.getLogger("src.database")
    
    log_data = {
        "operation": operation,
        "table": table,
        "duration": duration,
        "success": success,
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": "database_operation"
    }
    
    if record_count is not None:
        log_data["record_count"] = record_count
    
    if error:
        log_data["error"] = error
    
    if success:
        db_logger.info(f"Database {operation} on {table}", extra=log_data)
    else:
        db_logger.error(f"Database {operation} failed on {table}: {error}", extra=log_data)


def log_routing_decision(
    query_type: str,
    route_taken: str,
    confidence: float,
    processing_time: float,
    correction_applied: bool = False
):
    """
    Log routing decisions for system optimization.
    
    Args:
        query_type: Classified query type
        route_taken: Database/service route taken
        confidence: Classification confidence
        processing_time: Time taken for routing decision
        correction_applied: Whether self-correction was applied
    """
    routing_logger = logging.getLogger("src.routing")
    
    routing_logger.info("Query Routing Decision", extra={
        "query_type": query_type,
        "route_taken": route_taken,
        "confidence": confidence,
        "processing_time": processing_time,
        "correction_applied": correction_applied,
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": "routing_decision"
    })