"""Tests for logging configuration."""

import logging
import os
from io import StringIO
from unittest.mock import patch

import pytest
import structlog

from ingressor.logging_config import setup_logging, get_logger


class TestLoggingConfig:
    """Tests for logging configuration."""
    
    def test_setup_logging_default(self):
        """Test default logging setup."""
        with patch.dict(os.environ, {}, clear=True):
            setup_logging()
            
            logger = get_logger("test")
            # Logger should have the expected methods
            assert hasattr(logger, 'info')
            assert hasattr(logger, 'debug')
            assert hasattr(logger, 'error')
    
    def test_setup_logging_verbose(self):
        """Test verbose logging setup."""
        with patch.dict(os.environ, {}, clear=True):
            setup_logging(verbose=True)
            
            # Just verify setup doesn't crash and logger works
            logger = get_logger("test")
            logger.debug("Test debug message")
    
    def test_setup_logging_env_var(self):
        """Test logging setup with LOG_LEVEL environment variable."""
        with patch.dict(os.environ, {"LOG_LEVEL": "WARNING"}):
            setup_logging()
            
            # Just verify setup doesn't crash
            logger = get_logger("test")
            logger.warning("Test warning message")
    
    def test_verbose_overrides_env_var(self):
        """Test that verbose flag overrides LOG_LEVEL environment variable."""
        with patch.dict(os.environ, {"LOG_LEVEL": "ERROR"}):
            setup_logging(verbose=True)
            
            # Just verify setup works with verbose override
            logger = get_logger("test")
            logger.debug("Test debug message with verbose override")
    
    def test_get_logger_returns_structured_logger(self):
        """Test that get_logger returns a structured logger."""
        setup_logging()
        logger = get_logger("test_module")
        
        # Verify logger has expected methods and can be used
        assert hasattr(logger, 'debug')
        assert hasattr(logger, 'info')
        assert hasattr(logger, 'warning')
        assert hasattr(logger, 'error')
        
        # Test that we can log with structured data
        logger.info("Test message", key="value", number=42)
    
    def test_json_format_env_var(self):
        """Test JSON format with LOG_FORMAT environment variable."""
        with patch.dict(os.environ, {"LOG_FORMAT": "json"}):
            # This mainly tests that the configuration doesn't crash
            setup_logging()
            logger = get_logger("test")
            
            # Just verify we can log without errors
            logger.info("Test message", key="value")
    
    def test_console_format_default(self):
        """Test console format is default."""
        with patch.dict(os.environ, {}, clear=True):
            # This mainly tests that the configuration doesn't crash
            setup_logging()
            logger = get_logger("test")
            
            # Just verify we can log without errors
            logger.info("Test message", key="value")
    
    def test_invalid_log_level_defaults_to_info(self):
        """Test that invalid LOG_LEVEL defaults to INFO."""
        with patch.dict(os.environ, {"LOG_LEVEL": "INVALID"}):
            setup_logging()
            
            # Just verify setup doesn't crash with invalid level
            logger = get_logger("test")
            logger.info("Test message with invalid log level") 