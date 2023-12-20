"""The main package for applepy."""
import sys
from logging import getLogger
from types import TracebackType
from typing import Type

logger = getLogger(__name__)


def exception_handler(
    exception_type: Type[BaseException],
    exception: BaseException,
    _traceback: TracebackType | None,
) -> None:
    """Handle exceptions."""
    logger.error(f"Uncaught exception: {exception_type.__name__} - {exception}", exc_info=exception)


sys.excepthook = exception_handler
