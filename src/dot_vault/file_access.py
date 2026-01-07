import logging
import os
import platform
import re
from pathlib import Path, PureWindowsPath
from shutil import SameFileError, copyfile
from typing import Callable, Self, Type, Union

from returns.curry import partial
from returns.maybe import Maybe
from returns.result import Failure, Result, Success, safe

from dot_vault.constants import LIB_NAME
from dot_vault.xdg_directories import XDGUserDirectories

LOGGER = logging.getLogger()

#: Possible Errors in [`copy_file`][]
CopyFileError = Union[OSError, SameFileError]


def copy_file(
    source: Path, destination: Path, follow_symlinks: bool = True
) -> Result[Path, CopyFileError]:
    """Result-safe copy file function.

    Wraps [`shutil.copyfile`][]. It is intentional that the function is not defined
    using the [`retruns.result.safe`][] decorator, because as of `returns` version
    `0.26.0`, the decorator does not correctly relay typing information if more
    than one exception is specified in the list.

    Args:
        source: Passed to [`shutil.copyfile(src)`][shutil.copyfile]
        destination: Passed to [`shutil.copyfile(dst)`][shutil.copyfile]
        follow_symlinks: Passed to [`shutil.copyfile(follow_symlinks)`][shutil.copyfile]

    Returns:
        The `Some(..)` of the path to the destination file if everything succeed.
        Otherwise `Failure(..)` of the given types.
    """

    # explicit typehinting is not done here to avoid retyping the type definitions.
    # The typechecker will complain if the function signature and the list below does
    # not match.
    # Simply specifying tuple[type[Exception], ...] or something similar will result in
    # an error when trying to return the failure, since the path is to generic.
    types_to_check = (IOError, SameFileError)

    try:
        dst: Path = Path(copyfile(source, destination, follow_symlinks=follow_symlinks))
        return Success(dst)
    except types_to_check as e:
        return Failure(e)


@safe(exceptions=(OSError,))
def mkdir(path: Path, parents: bool = False, exist_ok: bool = False) -> Path:
    path.mkdir(parents=parents, exist_ok=exist_ok)
    return path


class CouldNotDetermineHostname(Exception):
    pass


class LongWindowsPathPrefixNotSupported(Exception):
    @classmethod
    def with_default_msg(cls: Type[Self]) -> Self:
        return cls("The long windows path prefix '//?/' is not supported.")


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
    """Get the path to the local dotfile library, and create it if it does not exist.

    Args:
        user: See [`get_local_dotfile_library_path`][]
        host: See [`get_local_dotfile_library_path`][]

    Returns:
        The Path itself or an error if either the path could not be created
        or something went wrong with [`get_local_dotfile_library_path`][].
    """

    PathOrError = Result[Path, OSError | CouldNotDetermineHostname]
    libpath: PathOrError = get_local_dotfile_library_path(user=user, host=host)

    f: Callable[[Path], PathOrError] = partial(mkdir, parents=True, exist_ok=True)
    libpath = libpath.bind(f)

    return libpath


def path_as_relative(path: Path) -> Result[Path, LongWindowsPathPrefixNotSupported]:
    """Make a path absolute and remove the root.

    On Windows drive letters will pre prependet with the ':'.
    `Path("C:/Users/name") -> Path("C/Users/name")`.

    Network drives will have the network name without any slashes prepended.
    `Path("//network/path/to/dir" -> Path("network/path/to/dir")`

    The long windows path prefix is not supported because prepending it
    to an absolute path and creating a `Path` object, erases the
    leading slash responsible for the root. Meaing the information of
    the path being relative or absolute is lost. I.e.: `Path("//?//var/log")` turns into
    `Path("//?/var/log")`.

    Args:
        path: Path to modify.

    Returns:
        Relative `Path` object.
    """

    path_str = str(path)

    win_long_path_prefix_pattern = r"^(\\|/){2}\?(\\|/)"
    win_long_path_prefix_match = re.match(win_long_path_prefix_pattern, path_str)
    has_win_long_path_prefix = win_long_path_prefix_match is not None
    if has_win_long_path_prefix:
        error = LongWindowsPathPrefixNotSupported.with_default_msg()
        return Failure(error)

    win_path = PureWindowsPath(path_str)
    drive_letter: str = win_path.drive.strip()
    posix_path: str = win_path.as_posix()
    has_drive_letter: bool = drive_letter != ""

    network_drive_pattern: str = r"^(\\|/){2}\w+(\\|/)\w+"
    is_network_drive: bool = re.match(network_drive_pattern, drive_letter) is not None

    if has_drive_letter:
        posix_path = posix_path.replace(drive_letter, "", count=1)
        drive_letter = drive_letter.rstrip(":")

    path = Path(posix_path).resolve()
    path_root: str = path.root
    path_str = str(path)

    path_relative_str: str = path_str.replace(path_root, "", count=1).lstrip("/\\")
    path_relative: Path = Path(path_relative_str)

    if has_drive_letter and not is_network_drive:
        path_relative = Path(drive_letter) / path_relative

    return Success(path_relative)
