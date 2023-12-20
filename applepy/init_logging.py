"""General module for initializing logging."""
import logging
from datetime import datetime
from os import getenv
from pathlib import Path
from socket import AF_INET, SOCK_STREAM, socket
from sys import gettrace
from typing import Final

from rich.console import Console
from rich.logging import RichHandler

from applepy.data_dirs import USER_LOG_DIR

START_TIME = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE_PATH: Final = Path(USER_LOG_DIR / f"{START_TIME}.log")


def setup_logging() -> logging.FileHandler:
    """
    Set up the logging environment.

    :return: The file handler used for logging.
    """
    USER_LOG_DIR.mkdir(parents=True, exist_ok=True)
    LOG_FILE_PATH.touch(exist_ok=True)

    file_handler = logging.FileHandler(LOG_FILE_PATH)
    # noinspection SpellCheckingInspection
    file_handler.setFormatter(logging.Formatter("%(asctime)s @%(name)-8s [%(levelname)s]: %(message)s\n"))
    file_handler.setLevel(logging.NOTSET)

    rich_handler = RichHandler(
        rich_tracebacks=True,
        markup=True,
        console=Console(width=192 if getenv("PYCHARM_HOSTED") else None),
    )
    rich_handler.setFormatter(logging.Formatter("%(message)s"))
    in_debug_environment = gettrace() is not None
    rich_handler.setLevel(logging.DEBUG if getenv("DEBUG") == "1" or in_debug_environment else logging.INFO)

    logging.basicConfig(
        handlers=[rich_handler, file_handler],
        level=logging.NOTSET,
    )

    _disable_logging()

    return file_handler


def _disable_logging() -> None:
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def upload_log() -> str:
    """Upload the log to termbin.com."""
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect(("termbin.com", 9999))
    sock.sendall(LOG_FILE_PATH.read_bytes())
    return sock.recv(1024).decode("utf-8")
