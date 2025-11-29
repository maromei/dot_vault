from returns.pipeline import is_successful
import logging
import shutil
from pathlib import Path

import pytest
from pytest_mock import MockerFixture
from returns.result import Success

from dot_vault.constants import LIB_NAME
from dot_vault.file_access import (
    LongWindowsPathPrefixNotSupported,
    get_local_dotfile_library_path,
    get_username,
    path_as_relative,
    copy_file
)
from dot_vault.xdg_directories import XDGUserDirectories

LOGGER = logging.getLogger(__name__)


class TestLibraryPaths:
    def test_get_local_lib_path(self, mocker: MockerFixture):
        hostname = "some_hostname"
        username = get_username()
        data_dir = XDGUserDirectories.data()

        get_hostname = mocker.patch("dot_vault.file_access.get_hostname")
        get_hostname.return_value = Success(hostname)

        value = get_local_dotfile_library_path()

        path_str = data_dir / LIB_NAME / username / hostname
        path = Path(path_str)

        assert value == Success(path)


def test_path_as_relative():
    paths = ("/var/config", "C:/drive/windows", "//network/drive/path")
    results = ("var/config", "C/drive/windows", "network/drive/path")

    def check_success(input, output):
        for i, o in zip(input, output):
            assert Success(Path(o)) == path_as_relative(Path(i))

    def check_failure(input, output):
        for i, o in zip(input, output):
            with pytest.raises(LongWindowsPathPrefixNotSupported):
                raise path_as_relative(Path(i)).failure()

    def add_long_win_path(str_):
        return f"//?/{str_}"

    def to_backwards_slash(str_):
        return str_.replace("/", "\\")

    check_success(paths, results)
    check_success([to_backwards_slash(p) for p in paths], results)

    check_failure([add_long_win_path(p) for p in paths], results)
    check_failure([to_backwards_slash(add_long_win_path(p)) for p in paths], results)


class TestCopyFile:

    def test_src_dst_them_same(self, tmp_path: Path):
        """The [`copy_file`][] function was constructed using the
        [`@safe`][returns.result.safe] decorator. As of `returns` version `0.26.0`,
        the decorator only catches `Exception` subclasses. Not `BaseException` subclasses.
        As of `dot_vault` version `0.0.4`, the [`copy_file`][] function uses
        [`shutil.copyfile`], which can raise the [`shutil.SameFileError`][]. It
        is unclear whether this exception can be caught using
        [`@safe`][returns.result.safe]. This is the test for it.
        """

        some_file_path: Path = tmp_path / "some_file.txt"
        some_file_path.write_text("some content.")

        result = copy_file(some_file_path, some_file_path)
        wrapped_error = result.failure()
        assert isinstance(wrapped_error, shutil.SameFileError)

    def test_successful_copy(self, tmp_path: Path):

        src_path: Path = tmp_path / "source_file.txt"
        dst_path: Path = tmp_path / "destination_file.txt"

        file_content = "Some content."
        src_path.write_text(file_content)

        result = copy_file(src_path, dst_path)
        assert is_successful(result)

        returned_dst_path: Path = result.unwrap()

        assert dst_path == returned_dst_path
        assert dst_path.is_file()

        generated_content: str = dst_path.read_text()
        assert generated_content == file_content

    def test_src_does_not_exist(self, tmp_path: Path):

        src_path: Path = tmp_path / "source_file.txt"
        dst_path: Path = tmp_path / "destination_file.txt"

        result = copy_file(src_path, dst_path)
        assert not is_successful(result)

        returned_error = result.failure()
        assert isinstance(returned_error, OSError)
