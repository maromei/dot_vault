import os
import platform
from pathlib import Path

from result import Result, Ok, Err

from dot_vault.xdg_directories import XDGUserDirectories


def get_username() -> str:
    return os.getlogin()


def get_hostname() -> Result[str, None]:
    hostname: str = platform.node()
    if hostname == "":
        return Err(None)
    return Ok(hostname)


def get_dotfile_library_path() -> Path:
    data_path = XDGUserDirectories.data
    return data_path /
