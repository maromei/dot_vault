"""Test for the [`Config`][dot_vault.config_model.Config] pydantic model."""

import json
import logging
from pathlib import Path

from returns.pipeline import is_successful
from returns.result import Failure, Result, Success

from dot_vault.config_model import Config, File, OnlyOn, ParseConfigError

LOGGER = logging.getLogger(__name__)


def get_some_valid_config_json_string() -> str:
    return '{"files": []}'


def test_empy_file_list():
    file_content: str = '{"files": []}'
    model: Result[Config, ParseConfigError] = Config.from_json_str(file_content)
    assert is_successful(model)


def test_incomplete_file_info():
    file_content: str = '{"files": [{}]}'
    model: Result[Config, ParseConfigError] = Config.from_json_str(file_content)
    assert not is_successful(model)


class TestConfigFromJson:
    def test_directory_as_input(self, tmp_path: Path):
        some_dir = tmp_path / "some_dir"
        some_dir.mkdir()

        res: Result[Config, ParseConfigError] = Config.from_json(some_dir)

        match res:
            case Success(value):
                assert False, f"An error should have been returned. Instead got {value}"
            case Failure(e):
                assert isinstance(e, ParseConfigError)
                source = e.source
                type_annotation = ParseConfigError.__annotations__["source"]  # pyright: ignore [reportAny]
                assert isinstance(source, type_annotation)
            case _:
                assert False, f"Invalid return type {type(res)}: {res}"

    def test_non_existant_file_as_input(self, tmp_path: Path):
        some_file = tmp_path / "some_file.txt"

        res: Result[Config, ParseConfigError] = Config.from_json(some_file)

        match res:
            case Success(value):
                assert False, f"An error should have been returned. Instead got {value}"
            case Failure(e):
                assert isinstance(e, ParseConfigError)
                source = e.source
                type_annotation = ParseConfigError.__annotations__["source"]  # pyright: ignore [reportAny]
                assert isinstance(source, type_annotation)
            case _:
                assert False, f"Invalid return type {type(res)}: {res}"

    def test_valid_file_as_input(self, tmp_path: Path):
        some_file = tmp_path / "some_file.txt"
        with open(some_file, "w+") as file:
            _ = file.write(get_some_valid_config_json_string())

        res: Result[Config, ParseConfigError] = Config.from_json(some_file)
        assert is_successful(res)


def test_file_name_as_key_validator():
    json_obj: dict[str, dict] = {
        "files": {
            "file_name_1": {"path": "/some/path_1", "only_on": {}},
            "file_name_2": {"path": "/some/path_2", "only_on": {}},
        }
    }
    json_str: str = json.dumps(json_obj)

    expected_file_list = Config(
        files=(
            File(name="file_name_1", path="/some/path_1", only_on=OnlyOn()),
            File(name="file_name_2", path="/some/path_2", only_on=OnlyOn()),
        )
    )

    parsed_config_result = Config.from_json_str(json_str)
    assert is_successful(parsed_config_result)

    parsed_config: Config = parsed_config_result.unwrap()
    assert parsed_config == expected_file_list
