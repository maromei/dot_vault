import logging
from pathlib import Path

from pydantic import ValidationError
from returns.pipeline import is_successful
from returns.result import Failure, Result, Success

from dot_vault.config_model import Config, File, ParseConfigError

CONFIG_PATH = Path("dotfile_sync_conf.json")
LOGGER = logging.getLogger()


def get_some_valid_config_json_string() -> str:
    return '{"files": []}'


class TestFile:
    def test_file_non_existant_path(self, tmp_path: Path):
        some_path = tmp_path / "does_not_exist.txt"

        try:
            _ = File(path=some_path)
            assert False, "A validation Error should occur on a non-existant path."
        except ValidationError:
            assert True

    def test_file_dir_as_input(self, tmp_path: Path):
        some_dir = tmp_path / "some_dir"
        some_dir.mkdir()

        try:
            _ = File(path=some_dir)
            assert False, "A validation Error should occur on a directory as input."
        except ValidationError:
            assert True

    def test_file_valid_input(self, tmp_path: Path):
        some_path = tmp_path / "some_file.txt"
        with open(some_path, "w+") as file:
            _ = file.write("Content.")

        try:
            _ = File(path=some_path)
            assert True
        except ValidationError:
            assert False, "The file exists, and should be parsed without issue."


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
