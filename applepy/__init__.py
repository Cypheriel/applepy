"""The main package for applepy."""
import sys
from logging import getLogger
from types import TracebackType
from typing import Type

from applepy.data_dirs import USER_DATA_DIR

CONFIG_PATH = USER_DATA_DIR / "config.json"

logger = getLogger(__name__)


def exception_handler(
    exception_type: Type[BaseException],
    exception: BaseException,
    _traceback: TracebackType | None,
) -> None:
    """Handle exceptions."""
    logger.error(f"Uncaught exception: {exception_type.__name__} - {exception}", exc_info=exception)


sys.excepthook = exception_handler
