"""Tests specifically for the [`FileIdentity`][] pydantic model."""

import json
import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from dot_vault.config_model import FileIdentity, FileSource

LOGGER = logging.getLogger(__name__)


def test_unique_source_names(tmp_path: Path):
    some_path: Path = tmp_path / "some_file.txt"
    with some_path.open("w+") as f:
        f.write("some_content")

    sources: list[FileSource] = [
        FileSource(path=some_path, name="1"),
        FileSource(path=some_path, name="2"),
        FileSource(path=some_path, name="3"),
    ]

    _ = FileIdentity(name="1", sources=sources)
    assert True

    sources.append(FileSource(path=some_path, name="2"))
    with pytest.raises(ValidationError):
        _ = FileIdentity(name="2", sources=sources)
