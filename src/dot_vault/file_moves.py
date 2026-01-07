"""Contains all function necessary to copy/link files between a host the library."""

import logging
from pathlib import Path
from typing import Union

from returns.pipeline import is_successful
from returns.result import Failure, Result, Success

from dot_vault.config_model import Config, FileIdentity, FileSource
from dot_vault.file_access import (
    CopyFileError,
    CouldNotDetermineHostname,
    LongWindowsPathPrefixNotSupported,
    copy_file,
    get_and_create_local_dotfile_library_path,
    mkdir,
)
from dot_vault.filter import FileFilter, filter_files_on_config

LOGGER = logging.getLogger()

#: Possible Errors / Exceptions when copying/linking/moving files to the the library.
ToLibraryErrors = Union[
    OSError,
    FileNotFoundError,
    NotADirectoryError,
    LongWindowsPathPrefixNotSupported,
    CopyFileError,
    CouldNotDetermineHostname,
]


def source_to_library(
    file_source: FileSource, identity_path: Path
) -> Result[None, ToLibraryErrors]:
    """Copies the specific file source to thepath in the identities library.

    The file mentioned in the `file_source` will be copied to 
    `{identity_path}/{file_source.name}/{file_source.path.name}`

    Args:
        file_source: Source to copy.
        indentity_path: Path to the library directory of the [`FileIdentity`][]
            Assumed to exist. Will not be created otherwise.

    Returns:
        `Some(None)` if all went well, otherwise the corresponding error.
    """

    if not file_source.path.is_file():
        return Failure(FileNotFoundError(str(file_source.path)))

    if not identity_path.is_dir():
        return Failure(NotADirectoryError(identity_path.as_posix()))

    target_dir: Path = identity_path / file_source.name
    target_path: Path = target_dir / file_source.path.name

    match mkdir(target_dir, parents=True, exist_ok=True):
        case Failure(_) as f:
            return f

    possible_copy_error: Result[Path, CopyFileError] = copy_file(
        file_source.path, target_path
    )
    return possible_copy_error.map(lambda x: None)


def identity_to_library(
    file_identity: FileIdentity, lib_path: Path
) -> Result[None, ToLibraryErrors]:
    """Copy all [`FileSource`][]s to the `dot_vault` library.

    Args:
        file_identity: `file_identity.sources` will be copied to the
            `lib_path / file_identity.name` directory.
        lib_path: Path to the library. Assumed to exist. Will not be created otherwise.

    Returns:
        `Some(None)` if all went well, otherwise the corresponding errors.
    """

    identity_path: Path = lib_path / file_identity.name

    match mkdir(identity_path, exist_ok=True):
        case Failure(_) as f:
            return f

    possible_error: Result[None, ToLibraryErrors] = Success(None)
    for file_source in file_identity.sources:
        possible_error = source_to_library(file_source, identity_path)
        if not is_successful(possible_error):
            break

    return possible_error


def files_to_library(
    config: Config,
    user: str | None = None,
    host: str | None = None,
    file_filter: FileFilter | None = None,
) -> Result[None, ToLibraryErrors]:
    """Copy all [`FileIdentity`][]s to the `dot_vault` library.

    The files and sources can be filtered before copying using the
    `file_filter`. Note that the `file_filter.user` and `file_filter.host` can
    be different from the `user` and `host` passed to this function. This may not yield
    useful results, but is still possible.

    Args:
        config: Config object with the file identities and sources to copy over.
        user: The user to build the local library path. See
            [`get_and_create_local_dotfile_library_path`][].
        host: The hostname to build the local library path. See
            [`get_and_create_local_dotfile_library_path`][]
        file_filter: Filters to apply to the config before copying the files.
            See [`filter_files_on_config`][]

    Returns:
        `Some(None)` if everything went fine, otherwise the error.
    """

    if file_filter is not None:
        config = filter_files_on_config(config, file_filter)

    match get_and_create_local_dotfile_library_path(user, host):
        case Success(lib_path):
            pass
        case f:
            return Failure(f.failure())

    possible_error: Result[None, ToLibraryErrors] = Success(None)
    for file_identity in config.files:
        possible_error = identity_to_library(file_identity, lib_path)
        if not is_successful(possible_error):
            break

    return possible_error
