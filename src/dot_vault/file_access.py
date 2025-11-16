import os
import platform
from pathlib import Path
from typing import Optional

from returns.result import Result, Failure, Success
from returns.pipeline import is_successful

from dot_vault.constants import LIB_NAME
from dot_vault.xdg_directories import XDGUserDirectories


def get_username() -> str:
    return os.getlogin()


def get_hostname() -> Result[str, OSError]:
    hostname: str = platform.node()
    if hostname == "":
        msg = "Could not determine the hostname."
        return Failure(OSError(msg))
    return Success(hostname)


def get_dotfile_library_path() -> Path:
    data_path: Path = XDGUserDirectories.data()
    return data_path / LIB_NAME


def get_local_dotfile_library_path(
    user: Optional[str] = None, hostname: Optional[str] = None
) -> Result[Path, OSError]:
    if user is None:
        user: str = get_username()

    match hostname:
        case None:
            hostname: Result[str, OSError] = get_hostname()
        case str():
            hostname: Result[str, OSError] = Success(hostname)
        case _:
            raise TypeError(f"`hostname` has an invalid type of '{type(hostname)}'")

    if not is_successful(hostname):
        return hostname

    hostname: Success[str]
    libpath: Path = get_dotfile_library_path() / user / hostname.ok_value

    return Success(libpath)
