from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Self

from pydantic import BaseModel, ConfigDict, FilePath, ValidationError, Field
from result import Err, Result, as_result

type __ParsedConfigFunc = Callable[[str], Result[Config, ValidationError]]


class File(BaseModel):
    path: FilePath


@dataclass
class ParseConfigError(Exception):
    source: ValidationError | OSError


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    files: list[File] = Field(default_factory=list)

    @classmethod
    def __model_validate_json_as_result(
        cls, json_str: str
    ) -> Result[Self, ParseConfigError]:
        fnc: __ParsedConfigFunc = as_result(ValidationError)(Config.model_validate_json)
        res: Result[Self, ValidationError] = fnc(json_str)
        return res.map_err(lambda e: ParseConfigError(e))

    @classmethod
    def from_json_str(cls, json_str: str) -> Result[Self, ParseConfigError]:
        return cls.__model_validate_json_as_result(json_str)

    @classmethod
    def from_json(cls, filepath: Path) -> Result[Self, ParseConfigError]:
        try:
            with open(filepath, "r") as file_connection:
                file_content = file_connection.read()
        except OSError as e:
            error_obj = ParseConfigError(e)
            return Err(error_obj)

        return cls.__model_validate_json_as_result(file_content)
