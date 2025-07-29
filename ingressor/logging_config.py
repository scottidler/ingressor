"""Logging configuration for ingressor using structlog."""

import logging
import os
import sys
from typing import Any, Dict

import structlog


def setup_logging(verbose: bool = False) -> None:
    """Setup structured logging configuration.
    
    Args:
        verbose: If True, enables DEBUG logging regardless of LOG_LEVEL env var
    """
    # Determine log level from environment or verbose flag
    if verbose:
        log_level = "DEBUG"
    else:
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    
    # Convert string to logging level
    numeric_level = getattr(logging, log_level, logging.INFO)
    
    # Configure stdlib logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=numeric_level,
    )
    
    # Configure structlog
    structlog.configure(
        processors=[
            # Add log level and timestamp
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="ISO"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            # Use JSON in production, console in development
            _get_renderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Set up logger for this module
    logger = structlog.get_logger(__name__)
    logger.info("Logging configured", log_level=log_level, verbose=verbose)


def _get_renderer() -> Any:
    """Get the appropriate log renderer based on environment."""
    # Use JSON in production (when LOG_FORMAT=json) or console otherwise
    log_format = os.getenv("LOG_FORMAT", "console").lower()
    
    if log_format == "json":
        return structlog.processors.JSONRenderer()
    else:
        return structlog.dev.ConsoleRenderer(
            colors=True,
            exception_formatter=structlog.dev.plain_traceback,
        )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a structured logger instance.
    
    Args:
        name: Logger name, typically __name__
        
    Returns:
        Configured structlog logger
    """
    return structlog.get_logger(name)


def log_function_entry(logger: structlog.stdlib.BoundLogger, func_name: str, **kwargs: Any) -> None:
    """Log function entry with parameters.
    
    Args:
        logger: The logger instance
        func_name: Name of the function being entered
        **kwargs: Function parameters to log
    """
    logger.debug("Function entry", function=func_name, **kwargs)


def log_function_exit(logger: structlog.stdlib.BoundLogger, func_name: str, **kwargs: Any) -> None:
    """Log function exit with return values.
    
    Args:
        logger: The logger instance
        func_name: Name of the function being exited
        **kwargs: Return values or exit status to log
    """
    logger.debug("Function exit", function=func_name, **kwargs)


def log_api_request(logger: structlog.stdlib.BoundLogger, method: str, path: str, **kwargs: Any) -> None:
    """Log API request details.
    
    Args:
        logger: The logger instance
        method: HTTP method
        path: Request path
        **kwargs: Additional request details
    """
    logger.info("API request", method=method, path=path, **kwargs)


def log_api_response(logger: structlog.stdlib.BoundLogger, method: str, path: str, status_code: int, **kwargs: Any) -> None:
    """Log API response details.
    
    Args:
        logger: The logger instance
        method: HTTP method
        path: Request path
        status_code: HTTP status code
        **kwargs: Additional response details
    """
    logger.info("API response", method=method, path=path, status_code=status_code, **kwargs)


def log_k8s_operation(logger: structlog.stdlib.BoundLogger, operation: str, cluster: str, **kwargs: Any) -> None:
    """Log Kubernetes operation details.
    
    Args:
        logger: The logger instance
        operation: Type of K8s operation
        cluster: Cluster name
        **kwargs: Additional operation details
    """
    logger.debug("Kubernetes operation", operation=operation, cluster=cluster, **kwargs)


def log_discovery_event(logger: structlog.stdlib.BoundLogger, event_type: str, **kwargs: Any) -> None:
    """Log service discovery events.
    
    Args:
        logger: The logger instance
        event_type: Type of discovery event
        **kwargs: Event details
    """
    logger.info("Discovery event", event_type=event_type, **kwargs) 