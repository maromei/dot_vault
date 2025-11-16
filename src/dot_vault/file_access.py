import os
import platform
from pathlib import Path
from typing import Optional

from returns.maybe import Maybe
from returns.result import Failure, Result, Success

from dot_vault.constants import LIB_NAME
from dot_vault.xdg_directories import XDGUserDirectories


def get_username() -> str:
    return os.getlogin()


def get_hostname() -> Result[str, str]:
    hostname: str = platform.node()
    if hostname == "":
        msg = "Could not determine the hostname."
        return Failure(msg)
    return Success(hostname)


def get_dotfile_library_path() -> Path:
    data_path: Path = XDGUserDirectories.data()
    return data_path / LIB_NAME


def get_local_dotfile_library_path(
    user: Optional[str] = None, hostname: Optional[str] = None
) -> Result[Path, str]:
    if user is None:
        user: str = get_username()

    hostname: Maybe[str] = Maybe.from_optional(hostname)
    hostname: Maybe[Success[str]] = hostname.map(Success)
    hostname: Result[str, str] = hostname.value_or(get_hostname())

    def generate_path(host: str) -> Path:
        return get_dotfile_library_path() / user / host

    libpath: Result[Path, str] = hostname.map(generate_path)
    return libpath
