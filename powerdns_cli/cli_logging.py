"""A custom logging handler module for collecting logs, messages, and success statuses.

This module provides the `ResultHandler` class, which extends `logging.Handler` to accumulate
log records,custom messages, and success statuses in a structured dictionary.
"""

import logging
from typing import Any

LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


class ResultHandler(logging.Handler):
    """A custom logging handler that collects logs, a message, and a success status.

    Attributes:
        result (Dict[str, Any]): A dictionary storing logs, a message, and a success status.
    """

    def __init__(self) -> None:
        """Initializes the ResultHandler with default values for the result dictionary."""
        super().__init__()
        self.result: dict[str, Any] = {
            "logs": [],
            "message": "",
            "success": None,
        }

    def emit(self, record: logging.LogRecord) -> None:
        """Appends the formatted log record to the logs list.

        Args:
            record (logging.LogRecord): The log record to format and append.
        """
        self.result["logs"].append(self.format(record))

    def set_message(self, message: str) -> None:
        """Sets the message in the result dictionary.

        Args:
            message (str): The message to set.
        """
        self.result["message"] = message

    def set_success(self, success: bool) -> None:
        """Sets the success status in the result dictionary.

        Args:
            success (Optional[bool]): The success status to set.
        """
        self.result["success"] = success

    def get_result(self) -> dict[str, Any]:
        """Returns the current result dictionary.

        Returns:
            Dict[str, Any]: The result dictionary containing logs, message, and success status.
        """
        return self.result
