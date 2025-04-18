import logging

# Create a logger specifically for the superadmin module
logger = logging.getLogger("superadmin")

# Set the minimum level of messages this logger will handle
logger.setLevel(logging.INFO)  # Can be DEBUG, INFO, WARNING, ERROR, CRITICAL

# Avoid adding multiple handlers if this module is imported more than once
if not logger.handlers:
    # Create a handler that outputs logs to the console (stdout)
    handler = logging.StreamHandler()

    # Define the log message format
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s in %(module)s: %(message)s"
    )

    # Apply the formatter to the handler
    handler.setFormatter(formatter)

    # Attach the handler to the logger
    logger.addHandler(handler)
