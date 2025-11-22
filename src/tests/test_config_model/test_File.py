"""Tests specifically for the [`File`][dot_vault.config_model.File] pydantic model."""

import json
import logging
from pathlib import Path

import pytest
from pydantic import ValidationError
from returns.maybe import Some

from dot_vault.config_model import File

LOGGER = logging.getLogger(__name__)


def test_file_non_existant_path(tmp_path: Path):
    some_path = tmp_path / "does_not_exist.txt"

    try:
        _ = File(path=some_path)
        assert False, "A validation Error should occur on a non-existant path."
    except ValidationError:
        assert True


def test_file_dir_as_input(tmp_path: Path):
    some_dir = tmp_path / "some_dir"
    some_dir.mkdir()

    try:
        _ = File(path=some_dir)
        assert False, "A validation Error should occur on a directory as input."
    except ValidationError:
        assert True


def test_file_valid_input(tmp_path: Path):
    some_path = tmp_path / "some_file.txt"
    with open(some_path, "w+") as file:
        _ = file.write("Content.")

    try:
        _ = File(path=some_path)
        assert True
    except ValidationError:
        assert False, "The file exists, and should be parsed without issue."


def test_name(tmp_path: Path):
    some_path = tmp_path / "some_file.txt"
    with open(some_path, "w+") as file:
        _ = file.write("Content.")

    name = "some-name"
    json_obj = {"path": str(some_path.resolve()), "name": name}
    file = File.model_validate_json(json.dumps(json_obj))
    assert file.name == Some(name)

    json_obj = {"path": str(some_path.resolve()), "name": "some name"}
    with pytest.raises(ValidationError):
        _ = File.model_validate_json(json.dumps(json_obj))
