import os
import platform
from enum import StrEnum
from pathlib import Path
from string import Formatter


class XDGUserDefaults(StrEnum):
    XDG_CONFIG_HOME = "{home}/.config"
    XDG_CACHE_HOME = "{home}/.cache"
    XDG_DATA_HOME = "{home}/.local/share"
    XDG_STATE_HOME = "{home}/.local/state"
    XDG_RUNTIME_DIR = "/run/user/{uid}"


class XDGUserDirectories:
    @classmethod
    def __format_default_string(cls, default: XDGUserDefaults) -> str:
        dir_path: str = default.value
        field_iterator = Formatter().parse(dir_path)
        argument_names = [
            field[1]
            for field in field_iterator
            if len(field) >= 2 and field[1] is not None
        ]

        is_linux = platform.system() == "Linux"
        uid_is_needed = "uid" in argument_names

        if not is_linux and uid_is_needed:
            raise OSError(
                f"Cannot generate the '{default.name}' value. A UID is needed, "
                + "which is only available on Linux platforms."
            )

        uid = ""
        if is_linux:
            uid = str(os.getuid())

        formatted_value: str = dir_path.format(home=cls.home, uid=uid)
        return formatted_value

    @classmethod
    def __build_path_with_home_and_uid(cls, default: XDGUserDefaults) -> Path:
        env_var: str = os.environ.get(
            default.name, cls.__format_default_string(default)
        )

        xdg_path = Path(env_var)
        if not xdg_path.is_dir():
            raise ValueError(f"The {default.name} directory is invalid: '{xdg_path}'")

        return xdg_path

    @classmethod
    def home(cls) -> Path:
        home_val = os.environ.get("HOME")
        if home_val is None:
            raise ValueError("The $HOME environment variable is not set.")
        home_path = Path(home_val)
        if not home_path.is_dir():
            raise ValueError(
                "The $HOME environment varibale points "
                + f"to an invalid directory '{home_path}'"
            )
        return home_path

    @classmethod
    def config(cls) -> Path:
        return cls.__build_path_with_home_and_uid(XDGUserDefaults.XDG_CONFIG_HOME)

    @classmethod
    def cache(cls) -> Path:
        return cls.__build_path_with_home_and_uid(XDGUserDefaults.XDG_CACHE_HOME)

    @classmethod
    def data(cls) -> Path:
        return cls.__build_path_with_home_and_uid(XDGUserDefaults.XDG_DATA_HOME)

    @classmethod
    def state(cls) -> Path:
        return cls.__build_path_with_home_and_uid(XDGUserDefaults.XDG_STATE_HOME)
