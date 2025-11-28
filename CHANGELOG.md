# Changelog

## [0.0.3] - 2025-11-28

### Added

- Added functions to filter file identities and sources.
    - `dot_vault.filter` module.
    - `filter_sources_on_file()`
    - `filter_files_on_config()`
- Added `FileSource.is_allowed()` as a wrapper for `OnlyOn.is_allowed()`.

### Fixes

- Fixed `mkdir`
    - Before it did not work at all.

### Misc

- Added Docstring to `get_and_create_local_dotfile_library_path()`

### Dev

- Added some dot-directories created by python tooling to be ignored.
- Added `mypy` as a typechecker alongside `pyrefly`
    - The `hatch` `typecheck` script now consists of calls to both `mypy` and
     `pyrefly`.
- Fixed some type incosistencies
- Added `dot_vault.filter__combine_possible_scalar_and_list()`
    - A utility for combining scalars and lists.
    - Crated to be used in filter functions.

## [0.0.2] - 2025-11-25

### Add

- Added the `dot_vault.config_model.field_as_key_validator()` function
    - It allows the transformation of nested dictionaries to a list of models
      in the `pydantic` validation stage.

### Changes

- Split the `File` class into `FileIdentity` and `FileSource`.
    - `FileIdentity` represents the conceptual file which might exist on
        multiple machines.
    - `FileSource` represents a single instance of a file on a single machine.
    - `FileIdentity` keeps a list to all the sources.
    - Both `Config.files`, aswell as `FileIdentity.sources` use the
        `field_as_key_validator()` function so they can also specified as
        a nested dictionary.

### Fixes

- The `dot_vault.file_access.mkdir()` function was fixed.
    - The definition contained typos in the return value and function calls.

### Developer only

- Removed unused imports.
- `pyrefly`
    - Added `pyrefly` config.
    - Added `pyrefly` ignore tags to `field_as_key_validator()` when refining
      types of the input values.
    - Added `pyrefly` ignore tags to false typing errors caused by the
      `returns` package. The package can only be fully statically typed using
      the provided `mypy` extension.
- Added the `lint`-hatch script with a `ruff check` call
    - The `lint` script is also added to the `check`-hatch script

## [0.0.1] - 2025-11-24

- Initial Release
- Very basic config pydantic model with options to specify file paths per username and hostname.
