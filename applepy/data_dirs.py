"""Module which contains the data directories for this project."""
from pathlib import Path
from typing import Final

from appdirs import AppDirs

import applepy

_PROJECT_NAME: Final = applepy.__name__
_AUTHOR: Final = "Cypheriel"

_APP_DIRS: Final = AppDirs(
    _PROJECT_NAME,
    _AUTHOR,
)

USER_LOG_DIR = Path(_APP_DIRS.user_log_dir)
USER_DATA_DIR = Path(_APP_DIRS.user_data_dir)
