import logging
import sys


def setup_logger():
    """
    Configure and return a logger instance that can be used across the application.

    Returns:
        A configured logger instance
    """
    # Get or create a logger with the given name
    logger = logging.getLogger()

    # change the log level no matter if it has been set up or not based on verbosity
    level = logging.DEBUG if verbose_mode else logging.INFO
    logger.setLevel(level)

    # Only configure handlers if they haven't been set up already
    if not logger.handlers:
        # Create a console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)

        # Create a formatter and add it to the handler
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(formatter)

        # Add the handler to the logger
        logger.addHandler(console_handler)
    elif logger.handlers[0].level != level:
        # remove the wrong console handler
        logger.removeHandler(logger.handlers[0])

        # Create a new console handler
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(level)

        # Create a formatter and add it to the handler
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(formatter)

        # Add the handler to the logger
        logger.addHandler(console_handler)


    return logger


# Global verbose flag that can be set by the main application
verbose_mode = False


def set_verbose_mode(verbose):
    """Set the global verbose mode flag."""
    global verbose_mode
    verbose_mode = verbose


def get_logger():
    """
    Get a logger configured with the application's global verbose setting.

    Returns:
        A configured logger instance
    """
    return setup_logger()