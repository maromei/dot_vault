import json
import logging
from pathlib import Path

from returns.maybe import Maybe, Nothing, Some
from returns.result import Result

from dot_vault.config_model import Config, ParseConfigError
from dot_vault.filter import __combine_possible_scalar_and_list, filter_files_on_config

LOGGER = logging.getLogger(__name__)


def test_combine_possible_scalar_and_list():
    assert __combine_possible_scalar_and_list(1, None) == Some([1])
    assert __combine_possible_scalar_and_list(None, [2, 3]) == Some([2, 3])
    assert __combine_possible_scalar_and_list(1, [2, 3]) == Some([1, 2, 3])
    assert __combine_possible_scalar_and_list(None, None) == Nothing


def test_combine_possible_scalar_and_list_mutability():
    list_: list[int] = [2, 3]
    result: Maybe[list[int]] = __combine_possible_scalar_and_list(1, list_)
    assert list_ == [2, 3]
    assert result == Some([1, 2, 3])


def test_combine_possible_scalar_and_list_nested_mutability():
    list_: list[list[str]] = [["2.1", "2.2"], ["3.1", "3.2"]]
    scalar: list[str] = ["1.1", "1.2"]
    result: Maybe[list[list[str]]] = __combine_possible_scalar_and_list(scalar, list_)
    assert list_ == [["2.1", "2.2"], ["3.1", "3.2"]]
    assert result == Some([["1.1", "1.2"], ["2.1", "2.2"], ["3.1", "3.2"]])


def test_config_filter(tmp_path: Path):
    file_list = [
        "source1.1.txt",
        "source1.2.txt",
        "source1.3.txt",
        "source2.1.txt",
    ]

    for file in file_list:
        with open(tmp_path / file, "w+") as f:
            f.write(file)

    json_obj: dict = {
        "files": {
            "file1": {
                "sources": {
                    "source1-1": {"path": str(tmp_path / "source1.1.txt")},
                    "source1-2": {
                        "path": str(tmp_path / "source1.2.txt"),
                        "only_on": {},
                    },
                    "source1-3": {
                        "path": str(tmp_path / "source1.3.txt"),
                        "only_on": {"username": ["pommy"]},
                    },
                }
            },
            "file2": {
                "sources": {"sources2-1": {"path": str(tmp_path / "source2.1.txt")}}
            },
        }
    }

    json_str: str = json.dumps(json_obj)
    config_result: Result[Config, ParseConfigError] = Config.from_json_str(json_str)
    config: Config = config_result.unwrap()

    filtered_config: Config = filter_files_on_config(config, user="pommy")
    expected_filenames = ["file1", "file2"]
    expected_sourcenames = ["source1-1", "source1-3", "sources2-1"]

    # fmt: off
    assert [file.name for file in filtered_config.files] == expected_filenames
    assert [
        source.name
        for file in filtered_config.files
        for source in file.sources
    ] == expected_sourcenames
    # fmt: on

    filtered_config = filter_files_on_config(config, user="pommy", file="file1")
    expected_filenames = ["file1"]
    expected_sourcenames = ["source1-1", "source1-3"]

    # fmt: off
    assert [file.name for file in filtered_config.files] == expected_filenames
    assert [
        source.name
        for file in filtered_config.files
        for source in file.sources
    ] == expected_sourcenames
    # fmt: on

    # shoulde be empty due to empty {} definition on only_on
    filtered_config = filter_files_on_config(config, source="source1-2")
    expected_filenames = []
    expected_sourcenames = []

    # fmt: off
    assert [file.name for file in filtered_config.files] == expected_filenames
    assert [
        source.name
        for file in filtered_config.files
        for source in file.sources
    ] == expected_sourcenames
    # fmt: on

    filtered_config = filter_files_on_config(config, source="source1-1")
    expected_filenames = ["file1"]
    expected_sourcenames = ["source1-1"]

    # fmt: off
    assert [file.name for file in filtered_config.files] == expected_filenames
    assert [
        source.name
        for file in filtered_config.files
        for source in file.sources
    ] == expected_sourcenames
    # fmt: on

    filtered_config = filter_files_on_config(
        config, source="source1-1", remove_empty_identities=False
    )
    expected_filenames = ["file1", "file2"]
    expected_sourcenames = ["source1-1"]

    # fmt: off
    assert [file.name for file in filtered_config.files] == expected_filenames
    assert [
        source.name
        for file in filtered_config.files
        for source in file.sources
    ] == expected_sourcenames
    # fmt: on
