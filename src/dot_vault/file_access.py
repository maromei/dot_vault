import os
import platform
from pathlib import Path

from returns.maybe import Maybe
from returns.result import Failure, Result, Success

from dot_vault.constants import LIB_NAME
from dot_vault.xdg_directories import XDGUserDirectories


class CouldNotDetermineHostname(Exception):
    pass


def get_username() -> str:
    return os.getlogin()


def get_hostname() -> Result[str, CouldNotDetermineHostname]:
    hostname: str = platform.node()
    if hostname == "":
        return Failure(CouldNotDetermineHostname())
    return Success(hostname)


def get_dotfile_library_path() -> Path:
    data_path: Path = XDGUserDirectories.data()
    return data_path / LIB_NAME


def get_local_dotfile_library_path(
    user: str | None = None, host: str | None = None
) -> Result[Path, CouldNotDetermineHostname]:
    username: str = Maybe.from_optional(user).value_or(get_username())
    hostname: Result[str, CouldNotDetermineHostname] = (
        Maybe.from_optional(host).map(Success).value_or(get_hostname())
    )

    def generate_path(host: str) -> Path:
        return get_dotfile_library_path() / username / host

    libpath: Result[Path, CouldNotDetermineHostname] = hostname.map(generate_path)
    return libpath
