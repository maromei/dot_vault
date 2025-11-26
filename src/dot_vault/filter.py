"""Contain function for filtering / querying sets of files specified in the config."""

import logging

from returns.maybe import Maybe, Nothing, Some

from dot_vault.config_model import Config, FileIdentity

LOGGER = logging.getLogger(__name__)


def __combine_possible_scalar_and_list[T](
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


def filter_sources_on_file(
    file: FileIdentity,
    user: str | None = None,
    host: str | None = None,
    source: str | None = None,
    source__in: list[str] | None = None,
) -> FileIdentity:
    """Filter the sources for a `FileIdentity`.

    Filter conditions for user-/hostname filtering will be 'and'-ed
    together with the source name condition.

    Args:
        user: If not `None`, each
            [`FileSource`][dot_vault.config_model.FileSource] will be checked
            whether the `user` and `host` combination is allowed.
            See
            [`FileSource.is_allowed()`][dot_vault.config_model.FileSource.is_allowed].
        host: If not `None`, each
            [`FileSource`][dot_vault.config_model.FileSource] will be checked
            whether the `user` and `host` combination is allowed.
            See
            [`FileSource.is_allowed()`][dot_vault.config_model.FileSource.is_allowed].
        source: If not `None`, only sources with the given name will be returned.
        source__in: If not `None`, only sources with names in the list will be returned.

    Return:
        A deepcopy of the `file` with the `sources` filtered based on the given rules.
    """

    file = file.model_copy(deep=True)
    sourcenames: Maybe[list[str]] = __combine_possible_scalar_and_list(
        source, source__in
    )

    source_list = []
    for file_source in file.sources:
        maybe_keep_source_on_name: Maybe[bool] = sourcenames.do(
            file_source.name in name_list for name_list in sourcenames
        )

        keep_source_on_name: bool = maybe_keep_source_on_name.value_or(True)
        keep_source_on_userhost: bool = file_source.is_allowed(
            username=user, hostname=host
        )

        if keep_source_on_name and keep_source_on_userhost:
            source_list.append(file_source)

    file.sources = source_list
    return file


def filter_files_on_config(
    config: Config,
    user: str | None = None,
    host: str | None = None,
    file: str | None = None,
    source: str | None = None,
    file__in: list[str] | None = None,
    source__in: list[str] | None = None,
    remove_empty_identities: bool = True
) -> Config:
    """Filter [`FileIdentity`]s and [`FileSource`]s.

    Each model is deepcopied, so none of the existing inputs are
    modified in place.

    Args:
        user: Username to check if a [`FileSource`] is available for the given
            user-/hostname combination.
        host: Hostname to check if a [`FileSource`] is available for the given
            user-/hostname combination.
        file: [`FileIdentity.name`] to filter for.
        source: [`FileSource.name`] to filter for.
        file__in: List of [`FileIdentity.name`]s to filter for.
        source__in: List of [`FileSource.name`]s to filter for.
        remove_empty_identities: Should a [`FileIdentity`] be dropped if the name is
            matched, but none of the [`FileSource`]s are?

    Returns:
        [`Config`] with a filtered [`files`][Config.file] list.
    """

    config = config.model_copy(deep=True)
    filenames: Maybe[list[str]] = __combine_possible_scalar_and_list(file, file__in)

    file_list = list[FileIdentity]()
    for file_identity in config.files:

        # fmt: off
        maybe_keep_file: Maybe[bool] = filenames.do(
            file_identity.name in name_list
            for name_list in filenames
        )
        # fmt: on

        keep_file: bool = maybe_keep_file.value_or(True)
        if not keep_file:
            continue

        filtered_file: FileIdentity = filter_sources_on_file(
            file=file_identity,
            user=user,
            host=host,
            source=source,
            source__in=source__in,
        )

        num_sources: int = len(filtered_file.sources)
        if remove_empty_identities and num_sources == 0:
            continue

        file_list.append(filtered_file)

    config.files = file_list
    return config
