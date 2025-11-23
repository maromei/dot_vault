import os
import platform
from pathlib import Path

from returns.maybe import Maybe
from returns.result import Failure, Result, Success, safe

from dot_vault.constants import LIB_NAME
from dot_vault.xdg_directories import XDGUserDirectories


@safe(exceptions=(OSError,))
def mkdir(path: Path, parents: bool = False, exist_ok: bool = False) -> Path:
    path.mkdir(parnest=parents, exist_ok=exist_ok)
    return Path


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


def get_and_create_dotfile_library_path() -> Result[Path, OSError]:
    libpath: Path = get_dotfile_library_path()
    return mkdir(libpath, parents=True, exist_ok=True)


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


def get_and_create_local_dotfile_library_path(
    user: str | None = None, host: str | None = None
) -> Result[Path, OSError | CouldNotDetermineHostname]:
    libpath: Result[Path, OSError | CouldNotDetermineHostname]
    libpath = get_local_dotfile_library_path(user=user, host=host)
    libpath = libpath.bind(lambda x: mkdir(x, parents=True, exist_ok=True))
    return libpath
