"""
This module is used to log the messages to the console or file.
"""

import logging
import re
import sty
import os

ATTENTION = 15


class ColorFormatter(logging.Formatter):
    """Formatter that injects ANSI colors for interactive console logs."""

    def format(self, record):
        res = super(ColorFormatter, self).format(record)
        if record.levelno >= logging.ERROR:
            res = sty.fg.red + sty.ef.bold + res + sty.rs.all
        elif record.levelno == logging.WARNING:
            res = sty.fg.yellow + res + sty.rs.all
        elif record.levelno == ATTENTION:
            res = sty.fg.green + sty.ef.bold + res + sty.rs.all
        return res


class NoColorFormatter(logging.Formatter):
    """Formatter that strips ANSI escapes for files and Windows terminals."""

    def format(self, record):
        res = super(NoColorFormatter, self).format(record)
        res = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", res)
        return res


def create_logger(
    name, output_type="file", level=logging.DEBUG, file_name="run_log.log"
):
    """
    Create a logger with file or console output.

    Creates a Python logging.Logger instance configured for either file
    or console output. File loggers use NoColorFormatter to remove ANSI
    escape codes, while console loggers use ColorFormatter for colored
    output on non-Windows systems.

    Args:
        name (str): Name of the logger instance
        output_type (str, optional): Output destination. Options:
            - 'file': Log to file (default)
            - 'console': Log to console/stdout
            Defaults to 'file'.
        level (int, optional): Logging level (e.g., logging.DEBUG, logging.INFO).
            Defaults to logging.DEBUG.
        file_name (str, optional): Path to log file when output_type is 'file'.
            Defaults to 'run_log.log'.

    Returns:
        logging.Logger: Configured logger instance

    Example:
        >>> from probejs.logger import create_logger
        >>> logger = create_logger('my_logger', output_type='console')
        >>> logger.info('Analysis started')
    """
    logger = logging.getLogger(name)

    # Close and remove existing handlers to prevent file creation
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)

    stream_handler = logging.StreamHandler()
    if os.name == "nt":  # Windows
        stream_handler.setFormatter(NoColorFormatter())
    else:
        stream_handler.setFormatter(ColorFormatter())

    logger.setLevel(level)

    if output_type == "file":
        file_handler = logging.FileHandler(filename=file_name, delay=True)
        file_handler.setFormatter(NoColorFormatter())
        logger.addHandler(file_handler)
    elif output_type == "console":
        logger.addHandler(stream_handler)

    return logger
