"""Tests specifically for the [`FileSource`][dot_vault.config_model.FileSource] pydantic model."""

import json
import logging
from pathlib import Path

import pytest
from pydantic import ValidationError
from pytest_mock import MockerFixture
from returns.pipeline import is_successful
from returns.result import Success

from dot_vault.config_model import FileSource

LOGGER = logging.getLogger(__name__)


def test_file_non_existant_path(tmp_path: Path):
    some_path = tmp_path / "does_not_exist.txt"

    try:
        _ = FileSource(path=some_path, name="some_name")
        assert False, "A validation Error should occur on a non-existant path."
    except ValidationError:
        assert True


def test_file_dir_as_input(tmp_path: Path):
    some_dir = tmp_path / "some_dir"
    some_dir.mkdir()

    try:
        _ = FileSource(path=some_dir, name="some_name")
        assert False, "A validation Error should occur on a directory as input."
    except ValidationError:
        assert True


def test_file_valid_input(tmp_path: Path):
    some_path = tmp_path / "some_file.txt"
    with open(some_path, "w+") as file:
        _ = file.write("Content.")

    try:
        _ = FileSource(path=some_path, name="some_name")
        assert True
    except ValidationError:
        assert False, "The file exists, and should be parsed without issue."


def test_name(tmp_path: Path):
    some_path = tmp_path / "some_file.txt"
    with open(some_path, "w+") as f:
        _ = f.write("Content.")

    name = "some-name"
    json_obj = {"path": str(some_path.resolve()), "name": name}
    file = FileSource.model_validate_json(json.dumps(json_obj))
    assert file.name == name

    json_obj = {"path": str(some_path.resolve()), "name": "some name"}
    with pytest.raises(ValidationError):
        _ = FileSource.model_validate_json(json.dumps(json_obj))


class TestOnlyOnSpecification:
    """Test if path validation works.

    The [`FileSource.path`][dot_vault.config_model.FileSource.path] will only check if the file
    exists, if it mentioned in the
    [`FileSource.only_on`][dot_vault.config_model.FileSource.only_on] field. If the
    [`FileSource.only_on`][dot_vault.config_model.FileSource.only_on] field is not specified,
    existance will always be checked. That case is implicitely checked by all tests
    outside of this class, which is why they are not repeated.
    """

    def test_empty_only_on_but_specified(self):
        """Test that if the `only_on` key is specified, but no actual values
        are present, no file existance check will be done.
        """

        json_obj = {"path": "/path/does/not/exist", "only_on": {}, "name": "name"}  # pyright: ignore [reportUnknownVariableType]
        json_str = json.dumps(json_obj)

        # No error should be generated here, eventhough the path does not exist.
        file = FileSource.model_validate_json(json_str)

        assert is_successful(file.only_on)
        assert isinstance(file.path, Path)

    def test_in_only_on_and_file_exists(self, tmp_path: Path, mocker: MockerFixture):
        """The `only_on` field is specified, with the current user@host combination
        being mentioned and the file exists.
        """

        get_username = mocker.patch("dot_vault.config_model.get_username")
        get_username.return_value = "user"

        get_hostname = mocker.patch("dot_vault.config_model.get_hostname")
        get_hostname.return_value = Success("host")

        file_path = tmp_path / "file"
        file_path.mkdir()
        file_path = file_path / "exists.txt"
        with open(file_path, "w+") as f:
            _ = f.write("Content.")

        json_obj = {
            "path": str(file_path),
            "only_on": {"username": ["user"], "hostname": ["host"]},
            "name": "name",
        }
        json_str = json.dumps(json_obj)

        file = FileSource.model_validate_json(json_str)
        assert is_successful(file.only_on)
        assert file.path == file_path

    def test_in_only_on_but_file_does_not_exist(self, mocker: MockerFixture):
        """The `only_on` field is specified, with the current user@host combination
        being mentioned. However, the file itself does not exist,
        resulting in a [`ValidationError`][pydantic.ValidationError].
        """

        get_username = mocker.patch("dot_vault.config_model.get_username")
        get_username.return_value = "user"

        get_hostname = mocker.patch("dot_vault.config_model.get_hostname")
        get_hostname.return_value = Success("host")

        json_obj = {
            "path": "path/does/not/exist",
            "only_on": {"username": ["user"], "hostname": ["host"]},
        }
        json_str = json.dumps(json_obj)

        error_match = r".*Path does not point to a file.*"
        with pytest.raises(ValidationError, match=error_match):
            _ = FileSource.model_validate_json(json_str)

    def test_no_verify_path_exception(self):
        """The `only_on` field is specified, but the current user@host combination
        is not mentioned. However, the given value in the json cannot be
        converted to a [`Path`][pathlib.Path] object, resulting in a
        [`ValidationError`][pydantic.ValidationError].
        """

        json_obj = {"path": 1234, "only_on": {}}  # pyright: ignore [reportUnknownVariableType]
        json_str = json.dumps(json_obj)

        error_match = r".*argument should be a str or an os\.PathLike object.*"
        with pytest.raises(ValidationError, match=error_match):
            _ = FileSource.model_validate_json(json_str)
