import unittest
import logging
import os
import tempfile
from unittest.mock import patch, MagicMock

from probejs.utils.logger import (
    ColorFormatter, NoColorFormatter, create_logger, ATTENTION
)


class TestColorFormatter(unittest.TestCase):
    def setUp(self):
        self.formatter = ColorFormatter()

    def test_color_formatter_error_level(self):
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="Error message",
            args=(),
            exc_info=None
        )
        
        formatted = self.formatter.format(record)
        
        self.assertIn("Error message", formatted)

    def test_color_formatter_warning_level(self):
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="test.py",
            lineno=1,
            msg="Warning message",
            args=(),
            exc_info=None
        )
        
        formatted = self.formatter.format(record)
        
        self.assertIn("Warning message", formatted)

    def test_color_formatter_attention_level(self):
        record = logging.LogRecord(
            name="test",
            level=ATTENTION,
            pathname="test.py",
            lineno=1,
            msg="Attention message",
            args=(),
            exc_info=None
        )
        
        formatted = self.formatter.format(record)
        
        self.assertIn("Attention message", formatted)

    def test_color_formatter_info_level(self):
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Info message",
            args=(),
            exc_info=None
        )
        
        formatted = self.formatter.format(record)
        
        self.assertIn("Info message", formatted)


class TestNoColorFormatter(unittest.TestCase):
    def setUp(self):
        self.formatter = NoColorFormatter()

    def test_no_color_formatter_removes_ansi_codes(self):
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Info message",
            args=(),
            exc_info=None
        )
        
        with patch('probejs.utils.logger.super') as mock_super:
            mock_super.return_value.format.return_value = "\x1b[31mError\x1b[0m"
            
            formatted = self.formatter.format(record)
            
            self.assertNotIn("\x1b", formatted)

    def test_no_color_formatter_preserves_text(self):
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None
        )
        
        formatted = self.formatter.format(record)
        
        self.assertIn("Test message", formatted)


class TestCreateLogger(unittest.TestCase):
    def setUp(self):
        self.test_log_file = tempfile.NamedTemporaryFile(delete=False, suffix='.log')
        self.test_log_file.close()

    def tearDown(self):
        if os.path.exists(self.test_log_file.name):
            os.remove(self.test_log_file.name)

    def test_create_logger_console(self):
        logger = create_logger("test_console", output_type="console")
        
        self.assertEqual(logger.name, "test_console")
        self.assertEqual(logger.level, logging.DEBUG)
        
        self.assertEqual(len(logger.handlers), 1)

    def test_create_logger_file(self):
        logger = create_logger(
            "test_file",
            output_type="file",
            file_name=self.test_log_file.name
        )
        
        self.assertEqual(logger.name, "test_file")
        self.assertEqual(logger.level, logging.DEBUG)
        
        self.assertEqual(len(logger.handlers), 1)
        
        logger.info("Test message")
        logger.handlers[0].flush()
        
        self.assertTrue(os.path.exists(self.test_log_file.name))

    def test_create_logger_custom_level(self):
        logger = create_logger(
            "test_level",
            output_type="console",
            level=logging.WARNING
        )
        
        self.assertEqual(logger.level, logging.WARNING)

    def test_create_logger_default_file_name(self):
        logger = create_logger("test_default", output_type="file")
        
        self.assertEqual(len(logger.handlers), 1)

    def test_create_logger_replaces_handlers(self):
        logger = create_logger("test_replace", output_type="console")
        
        initial_handlers = len(logger.handlers)
        
        logger = create_logger("test_replace", output_type="console")
        
        self.assertEqual(len(logger.handlers), initial_handlers)

    def test_create_logger_file_handler_has_no_color_formatter(self):
        logger = create_logger(
            "test_no_color",
            output_type="file",
            file_name=self.test_log_file.name
        )
        
        handler = logger.handlers[0]
        
        self.assertIsInstance(handler, logging.FileHandler)
        
        logger.handlers[0].flush()

    def test_create_logger_with_windows(self):
        with patch('probejs.utils.logger.os.name', 'nt'):
            logger = create_logger("test_windows", output_type="console")
            
            self.assertEqual(logger.name, "test_windows")
            self.assertEqual(len(logger.handlers), 1)

    def test_create_logger_message_logged(self):
        logger = create_logger("test_logging", output_type="console")
        
        with patch.object(logger.handlers[0], 'emit') as mock_emit:
            logger.info("Test info")
            self.assertTrue(mock_emit.called)
            
            logger.warning("Test warning")
            self.assertTrue(mock_emit.called)
            
            logger.error("Test error")
            self.assertTrue(mock_emit.called)


if __name__ == "__main__":
    unittest.main()
