"""Contain function for filtering / querying sets of files specified in the config."""

import logging
from dataclasses import dataclass

from returns.maybe import Maybe, Nothing, Some

from dot_vault.config_model import Config, FileIdentity

LOGGER = logging.getLogger(__name__)


def _combine_possible_scalar_and_list[T](
    scalar: T | None, vec: list[T] | None
) -> Maybe[list[T]]:
    """Combines an optional scalar and list.

    Args:
        scalar: Optional single value
        vec: Optional list of values

    Returns:
        A list of values, either of `vec` with the `scalar` inserted,
        or a list with only the `scalar` value.
        [`Nothing`][returns.maybe.Nothing] is only returned if both input values
        are [`Nothing`][returns.maybe.Nothing]. Note that the input list is always
        copied, and no inplace modifications will be done.
    """

    maybe_scalar = Maybe.from_optional(scalar)
    maybe_vec = Maybe.from_optional(vec)

    # The approach here is to just explicitely name all 4 possible input
    # combinations and define the output.
    # Assuming the types are respected, everything is well defined.
    match maybe_scalar, maybe_vec:
        case Some(value), Some(list_):
            return Some([value, *list_])
        case Some(value), Maybe.empty:
            return Some([value])
        case Maybe.empty, Some(list_):
            return Some(list_)
        case Maybe.empty, Maybe.empty:
            return Nothing

    # This should never be reached

    raise ValueError(
        "Something unexpected went wrong when combining scalar and list optionals.\n"
        f"Scalar: {scalar}\n"
        f"List: {vec}"
    )


@dataclass
class FileFilter:
    """Is used to specify keywords for functions used to filter files.

    See f.e. [`filter_source_on_file`][] or [`filter_files_on_config`][].
    """

    #: Username to check if a [`FileSource`][] is available for the given
    #: user-/hostname combination.
    user: str | None = None

    #: Hostname to check if a [`FileSource`][] is available for the given
    #: user-/hostname combination.
    host: str | None = None

    file: str | None = None  #: [`FileIdentity.name`][] to filter for.

    #: [`FileSource.name`][`dot_vault.config_model.FileSource.name`] to filter for.
    source: str | None = None

    file__in: list[str] | None = None  #: List of `file`s to filter for.
    source__in: list[str] | None = None  #: List of `source`s to filter for.

    #: Should a [`FileIdentity`][] be dropped if the name is
    #: matched, but none of the [`FileSource`][dot_vault.config_model.FileSource]s are?
    remove_empty_identities: bool = True

    @property
    def filenames(self) -> Maybe[list[str]]:
        """Joins `file` and `file__in` into a single list.

        Returns:
            [`Some()`][] of a list of values specified in `file` and/or `file__in`.
            If both fields are `None`, [`Nothing`][] is returned.
        """
        return _combine_possible_scalar_and_list(self.file, self.file__in)

    @property
    def sourcenames(self) -> Maybe[list[str]]:
        """Joins `source` and `source__in` into a single list.

        Returns:
            [`Some()`][] of a list of values specified in `source` and/or `source__in`.
            If both fields are `None`, [`Nothing`][] is returned.
        """
        return _combine_possible_scalar_and_list(self.source, self.source__in)


def filter_sources_on_file(file: FileIdentity, file_filter: FileFilter) -> FileIdentity:
    """Filter the sources for a `FileIdentity`.

    Filter conditions for user-/hostname filtering will be 'and'-ed
    together with the source name condition.

    Args:
        file: [`FileIdentity`][] which will be filtered.
        file_filter: Contains filter definitions to apply.

    Return:
        A deepcopy of the `file` with the `sources` filtered based on the given rules.
    """

    file = file.model_copy(deep=True)

    source_list = []
    for file_source in file.sources:
        maybe_keep_source_on_name: Maybe[bool] = Maybe.do(
            file_source.name in name_list for name_list in file_filter.sourcenames
        )

        keep_source_on_name: bool = maybe_keep_source_on_name.value_or(True)
        keep_source_on_userhost: bool = file_source.is_allowed(
            username=file_filter.user, hostname=file_filter.host
        )

        if keep_source_on_name and keep_source_on_userhost:
            source_list.append(file_source)

    file.sources = source_list
    return file


def filter_files_on_config(config: Config, file_filter: FileFilter) -> Config:
    """Filter [`FileIdentity`]s and [`FileSource`]s.

    Each model is deepcopied, so none of the existing inputs are
    modified in place.

    Args:
        config: [`Config`][] which will be filtered.
        file_filter: Contains filter definitions to apply.

    Returns:
        [`Config`] with a filtered [`files`][Config.file] list.
    """

    config = config.model_copy(deep=True)

    file_list = list[FileIdentity]()
    for file_identity in config.files:
        # fmt: off
        maybe_keep_file: Maybe[bool] = Maybe.do(
            file_identity.name in name_list
            for name_list in file_filter.filenames
        )
        # fmt: on

        keep_file: bool = maybe_keep_file.value_or(True)
        if not keep_file:
            continue

        filtered_file: FileIdentity = filter_sources_on_file(
            file=file_identity, file_filter=file_filter
        )

        num_sources: int = len(filtered_file.sources)
        if file_filter.remove_empty_identities and num_sources == 0:
            continue

        file_list.append(filtered_file)

    config.files = file_list
    return config
