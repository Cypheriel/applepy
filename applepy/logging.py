import logging
from os import getenv
from socket import AF_INET, SOCK_STREAM, socket
from sys import gettrace
from tempfile import NamedTemporaryFile

from rich.console import Console
from rich.logging import RichHandler

log_file = NamedTemporaryFile(delete=False)
logger = logging.getLogger(__name__)

file_handler = logging.FileHandler(log_file.name)
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


def setup_logging():
    logging.basicConfig(
        handlers=[rich_handler, file_handler],
        level=logging.NOTSET,
    )

    _disable_logging()


def _disable_logging():
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def upload_log() -> str:
    log_file.seek(0)

    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect(("termbin.com", 9999))
    sock.sendall(log_file.read())
    return sock.recv(1024).decode("utf-8")
