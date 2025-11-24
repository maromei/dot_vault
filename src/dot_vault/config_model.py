import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, ClassVar, Final, TypeVar, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    FilePath,
    ValidationError,
    ValidationInfo,
    ValidatorFunctionWrapHandler,
    computed_field,
    field_validator,
    model_validator,
)
from returns.maybe import Maybe
from returns.result import Failure, Result, Success

from dot_vault.file_access import get_hostname, get_username

type __ParsedConfigFunc = Callable[[str], Result[Config, ValidationError]]


LOGGER = logging.getLogger(__name__)


def field_as_key_validator(
    values: dict[str, Any], list_field_name: str, field_name: str
) -> dict[str, Any]:
    """Transform nested dicts to a list of dicts with the first level key as an item.

    This validator is intended to be used with Pydantic's
    `model_validator(mode="before")`.

    The function transforms

    ```python
    values = {
        "{list_field_name}": {
            "value_1": {...},
            "value_2": {...},
        }
    }
    ```

    to

    ```python
    values = {
        "{list_field_name}": [
            {"{field_name}": "value_1", ...},
            {"{field_name}": "value_2", ...},
        ]
    }
    ```

    Args:
        values: The dictionary of values being validated by Pydantic.
        list_field_name: The name of the field in `values` that contains the nested
            dictionaries to be transformed.
        field_name: The item key, to which the first level key should be assigned.

    Returns:
        If the object at `list_field_name` does not confom to the
        `dict[str, dict]` signature, no modifications are done, and the `values`
        input are returned as-is. Otherwise the described modification is done
        to the `values` input and returned.

    Raises:
        ValueError: If `list_field_name` is not found in the `values` dictionary.

    """
    UnknownObj = TypeVar("UnknownObj")

    if list_field_name not in values.keys():
        value_str: str = repr(values)
        raise ValueError(
            "Error when setting a keyname as a Model field:\n"
            f"Could not find list_field_name '{list_field_name}' in the values "
            f"dictionary:\n{value_str}"
        )

    list_field: dict[Any, Any] | UnknownObj = values[list_field_name]
    if not isinstance(list_field, dict):
        return values
    list_field: dict[Any, Any]

    keys_are_str = all((isinstance(key, str) for key in list_field.keys()))
    if not keys_are_str:
        return values
    list_field: dict[str, Any]

    values_are_dict = all((isinstance(value, dict) for value in list_field.values()))
    if not values_are_dict:
        return values
    list_field: dict[str, dict]

    key: str
    value: dict
    for key, value in list_field.items():
        value[field_name] = key

    values[list_field_name] = list(list_field.values())
    return values


class OnlyOn(BaseModel):
    """Specify user and hostname combinations to signal limited applicability.

    The class provides three lists. Each entry represents one allowed value.
    F.e. `username = ["yuki", "emi", "pommy"]` means all of these users are
    allowed to do whatever this object is attached to, regardless of their hostname.

    The `userhost` attribute allows for combinations of user and hostname to be more
    specific. F.e. `userhost = ["pommy@pommys-pad]` will only allow this specific
    combination. Partial definitions are allowed aswell, which is denoted via an `@`
    symbol. Meaning the following definitions are equivalent::

        OnlyOn(username=["emi"], hostname=["yukis-yacht"], userhost=["pommy@pommys-pad"])
        OnlyOn(userhost=["emi@", "@yukis-yacht", "pommy@pommys-pad"])

    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")

    username: list[str] = Field(default_factory=list)  #: Allowed usernames.
    hostname: list[str] = Field(default_factory=list)  #: Allowed hostnames.

    #: Allowed user hostname combinations.
    #:
    #: User and hostname are divided via the `@` symbol: `user@hostname`.
    #: Partial definitions are allowed aswell. Meaning `userhost = ["@hostname"]` is
    #: the same as `hostname = ["hostname"]` and `userhost = ["user@"]` is the same as
    #: `username = ["user"]`
    #:
    #: Each entry in this list will use the
    #: [`OnlyOn.userhost_entries_staisfy_pattern`][dot_vault.config_model.OnlyOn.userhost_entries_staisfy_pattern]
    #: validator to check for compliance of the format.
    userhost: list[str] = Field(default_factory=list)

    @classmethod
    def build_userhost_pattern(cls) -> str:
        """Build the regex pattern to which `userhost` has to adhere.

        Build regex to match 'user@host', where at most one group (user or host) can
        be left off. Allowed characters a letters, digits, underscore and '-'.

        Returns:
            regex string.

        """

        allowed_characters: str = r"\w\-"
        allowed_characterset: str = f"[{allowed_characters}]+"

        # We want to match the pattern user@host with partial presenence.
        # Meaning user@ and @host are valid, but '@' is not. At least
        # a single group needs to be present.
        # --> We just construct an 'or' regex with each individual option instead
        # of doing something fancy. Meaning:
        # (option1)|(option2)|(option3)
        username: str = f"{allowed_characterset}@"
        hostname: str = f"@{allowed_characterset}"
        userhost: str = f"{allowed_characterset}@{allowed_characterset}"

        # Wrap each option with the starting and end characters ('^', '$') and
        # brackets for the capture group.
        options: list[str] = [
            f"(^{option}$)" for option in (username, hostname, userhost)
        ]
        combined_options = "|".join(options)
        return combined_options

    def generate_full_allowed_set(self) -> set[str]:
        """Generate a set of allowed username-hostname combinations.

        Returns:
            A set with valid usernames and/or hostnames. All values are specified with
            the `@` character, including partially defined combinations.
            Meaning, the following characters are possible:
            `user@`, `@hostname`, `user@hostname`

        """
        users = {f"{user}@" for user in self.username}
        hosts = {f"@{host}" for host in self.hostname}

        userhosts = set(self.userhost)
        userhosts = userhosts.union(users).union(hosts)

        return userhosts

    def is_allowed(
        self, username: str | None = None, hostname: str | None = None
    ) -> bool:
        """Check whether the given username@hostname combination is allowed.

        Returns:
            If either the username or hostname is found in its respective list,
            or if the specific combination is found in the `hostname` list.

        """
        all_allowed_values: set[str] = self.generate_full_allowed_set()
        set_to_check: set[str] = set()

        if username is not None:
            set_to_check.add(f"{username}@")

        if hostname is not None:
            set_to_check.add(f"@{hostname}")

        if username is not None and hostname is not None:
            userhost = f"{username}@{hostname}"
            set_to_check.add(userhost)

        intersection: set[str] = all_allowed_values.intersection(set_to_check)
        return len(intersection) != 0

    @field_validator("userhost", mode="after")
    @classmethod
    def userhost_entries_satisfy_pattern(cls, userhost_list: list[str]) -> list[str]:
        """Check that each entry in the `hostname` field is correctly formatted.

        Every entry will be validated using the pattern generated by
        [`OnlyOn.build_userhost_pattern()`][dot_vault.config_model.OnlyOn.build_userhost_pattern].

        Args:
            userhost_list: List to validate.

        Raises:
            ValueError: If any of the values in the list do not match the pattern.
                Every single value will be checked. If more than one value
                are invalid, all of them will appear in the error message.

        Returns:
            The validated list if validation was sucessful.

        """
        userhost_pattern = cls.build_userhost_pattern()
        pattern = re.compile(userhost_pattern)
        invalid_entries: list[str] = list()
        for entry in userhost_list:
            match = pattern.match(entry)
            if match is None:
                invalid_entries.append(entry)

        if (len(invalid_entries)) == 0:
            return userhost_list

        invalid_entries = [f"'{entry}'" for entry in invalid_entries]
        entry_list_str: str = ", ".join(invalid_entries)
        entry_singular_plural = "entry"

        if len(invalid_entries) > 1:
            entry_singular_plural = "entries"
            entry_list_str = f"[{entry_list_str}]"

        error_msg = (
            f"The userhost {entry_singular_plural} {entry_list_str} does not meet "
            + "the required pattern of 'user@host'."
        )
        raise ValueError(error_msg)


class File(BaseModel):
    """A single file.

    The [`path`][dot_vault.config_model.File.path] will be checked for existance,
    if the current [`user`][dot_vault.file_access.get_username] and
    [`hostname`][dot_vault.file_access.get_hostname] combination is mentioned in the
    [`only_on`][dot_vault.config_model.File.only_on] field, or if the
    [`only_on`][dot_vault.config_model.File.only_on] field is not specified.

    Note:
        You can pass an empty dictionary to the
        [`only_on`][dot_vault.config_model.File.only_on] field to never check for
        the existance of the given file.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", arbitrary_types_allowed=True
    )

    #: Internal definition for [`only_on`][dot_vault.config_model.File.only_on].
    #
    #: Due to the path validation, this field has to be defined above the `path` field.
    #: See [`File.check_path_only_on`][dot_vault.config_model.File.check_path_only_on].
    only_on_internal: OnlyOn | None = Field(default=None, alias="only_on")

    #: The path to the file.
    #:
    #: Will be checked for existance if the current system (username / hostname) is
    #: found in the [`only_on`][dot_vault.config_model.File.only_on] field.
    #:
    #: For the path validation via
    #: [`File.check_path_only_on`][dot_vault.config_model.File.check_path_only_on]
    #: to work, this field has to be defined after the
    #: [`only_on_internal`][dot_vault.config_model.File.only_on_internal] field.
    #: See [`File.check_path_only_on`][dot_vault.config_model.File.check_path_only_on]
    #: for more details.
    path: FilePath

    #: Internal representation of the `name` property.
    #:
    #: In order for [`name`][dot_vault.config_model.File.name] to be of type
    #: [`Maybe`][returns.maybe.Maybe], instead of just `str|None`, it has to
    #: wrap some internal representation.
    name_internal: str | None = Field(
        default=None, alias="name", exclude=True, pattern=r"^[\w\-]+$"
    )

    @computed_field
    @property
    def name(self) -> Maybe[str]:
        """Optional name for the file.

        It is essentially an alias for the given file. The name
        itself does not need to be unique in the config, rather it
        should be repeated for multiple files on multiple device to
        make sync tasks easier.

        The name itself is only allowed to contain letters, digits, underscores and
        the '-' character.
        """
        return Maybe.from_optional(self.name_internal)

    @computed_field
    @property
    def only_on(self) -> Maybe[OnlyOn]:
        """Defines on which username / hostname the file should be found.

        Property wrapper around the
        [`only_on_internal`][dot_vault.config_model.File.only_on_internal] field,
        to return it as a [`Maybe`][returns.maybe.Maybe] type.

        If the entry is not specified, it is assumed to always be found.
        If the entry is specified but empty, the file i assumed to never be found.
        """
        return Maybe.from_optional(self.only_on_internal)

    @field_validator("path", mode="wrap")
    @classmethod
    def check_path_only_on(
        cls,
        value: Any,  # pyright: ignore [reportAny, reportExplicitAny]
        handler: ValidatorFunctionWrapHandler,
        values: ValidationInfo,
    ) -> Path:
        """Validator for the file path.

        Checks whether the file exists, if the current username / hostname
        is found in the [`only_on`][dot_vault.config_model.File.only_on] field or
        if [`only_on`][dot_vault.config_model.File.only_on] is `Nothing`.

        Due to the dependency on the [`only_on`][dot_vault.config_model.File.only_on]
        field, it needs to be specified before the
        [`path`][dot_vault.config_model.File.path] field, otherwise it will not
        be present in the `values` parameter, which will be passed to the function
        from `pydantic`.

        Args:
            value: The value to be validated.
            handler: `pydantic` validation handler.
            values: `pydantic` object containing information about the fields and
                the object to be generated.

        Returns:
            The validated path.

        Raises:
            ValueError: If the fields for retrieving the validated `only_on` field
                cannot be found.
            Exception: Generically raises an exception if the conversion of
                the value to a path failes, if no existance checks via pydantic is done.

        """

        existing_fields: dict[str, Any] = values.data  # pyright: ignore [reportExplicitAny]
        only_on_key: Final[str] = "only_on_internal"
        only_on_key_present: bool = only_on_key in existing_fields.keys()

        if not only_on_key_present:
            raise ValueError(
                f"Error when validating the file path '{value}'. "
                + f"Unable to find the '{only_on_key}' field."
            )

        only_on_optional: OnlyOn | None = existing_fields.get(only_on_key)
        only_on: Maybe[OnlyOn] = Maybe.from_optional(only_on_optional)

        username: str = get_username()
        hostname: str | None = get_hostname().value_or(None)

        def map_allowed(only_on: OnlyOn):
            return only_on.is_allowed(username=username, hostname=hostname)

        maybe_allowed: Maybe[bool] = only_on.map(map_allowed)
        is_allowed: bool = maybe_allowed.value_or(True)

        if is_allowed:
            return cast(Path, handler(value))

        # The only validation done here, is whether the `Path` object can be created.
        # The error is reraised as a `ValueError`, so `pydantic` will internally deal
        # with it and translate it to a `ValidationError`.
        try:
            path = Path(value)  # pyright: ignore [reportAny]
        except Exception as e:
            raise ValueError(e)

        return path


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

    @model_validator(mode="before")
    @classmethod
    def __file_name_as_key(cls, values: dict[str, Any]):
        return field_as_key_validator(values, "files", "name")

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
