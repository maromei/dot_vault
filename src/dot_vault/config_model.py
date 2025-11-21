from dataclasses import dataclass
from pathlib import Path
from typing import Callable, ClassVar

from pydantic import BaseModel, ConfigDict, Field, FilePath, ValidationError
from returns.result import Failure, Result, Success

type __ParsedConfigFunc = Callable[[str], Result[Config, ValidationError]]


class File(BaseModel):
    path: FilePath


@dataclass
class ParseConfigError(Exception):
    source: ValidationError | OSError


class Config(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")
    files: list[File] = Field(default_factory=list)

    @classmethod
    def __model_validate_json_as_result(
        cls, json_str: str
    ) -> Result["Config", ParseConfigError]:
        try:
            result = Config.model_validate_json(json_str)
        except ValidationError as e:
            error_obj = ParseConfigError(e)
            return Failure(error_obj)
        return Success(result)

    @classmethod
    def from_json_str(cls, json_str: str) -> Result["Config", ParseConfigError]:
        return cls.__model_validate_json_as_result(json_str)

    @classmethod
    def from_json(cls, filepath: Path) -> Result["Config", ParseConfigError]:
        try:
            with open(filepath, "r") as file_connection:
                file_content = file_connection.read()
        except OSError as e:
            error_obj = ParseConfigError(e)
            return Failure(error_obj)

        return cls.__model_validate_json_as_result(file_content)
