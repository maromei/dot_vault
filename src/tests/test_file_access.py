import logging
from pathlib import Path

from pytest_mock import MockerFixture
from returns.result import Success

from dot_vault.constants import LIB_NAME
from dot_vault.file_access import get_local_dotfile_library_path, get_username
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
