"""Tests specifically for the [`OnlyOn`][dot_vault.config_model.OnlyOn] pydantic model."""

import json
import logging
import re

import pytest
from pydantic import ValidationError

from dot_vault.config_model import OnlyOn

LOGGER = logging.getLogger(__name__)


def test_only_on_userhost_pattern():
    userhost_pattern = OnlyOn.build_userhost_pattern()
    pattern = re.compile(userhost_pattern)

    # Simply check for the '-' character, as it not included by default in the
    # \w regex modifier.
    assert pattern.match("-@-") is not None

    assert pattern.match("NoAtSymbol") is None
    assert pattern.match("@") is None
    assert pattern.match("hello @") is None
    assert pattern.match("@s ome") is None
    assert pattern.match("invalid_left valid@name invalid_right") is None

    assert pattern.match("hello@some") is not None
    assert pattern.match("hello@") is not None
    assert pattern.match("@some") is not None

    assert pattern.match("h3ll0@s0m3") is not None
    assert pattern.match("h3ll0@") is not None
    assert pattern.match("@50m3") is not None

    assert pattern.match("h_l_l_0@5_0_m_3") is not None
    assert pattern.match("h_l_l_0@") is not None
    assert pattern.match("@5_0_m_3") is not None


def test_disallow_extra_inputs():
    with pytest.raises(ValidationError, match=r".*Extra inputs are not permitted.*"):
        obj = {"DoesNotExist": ["user@host"]}
        _ = OnlyOn.model_validate_json(json.dumps(obj))


class TestUserHostnameListValidation:
    def test_simple_valid_values(self):
        obj = {"userhost": ["user@host"]}
        _ = OnlyOn.model_validate_json(json.dumps(obj))

        obj = {"userhost": ["user@"]}
        _ = OnlyOn.model_validate_json(json.dumps(obj))

        obj = {"userhost": ["@host"]}
        _ = OnlyOn.model_validate_json(json.dumps(obj))

    def test_empty_object(self):
        _ = OnlyOn.model_validate_json("{}")
        assert True

    def test_single_value_invalid(self):
        error_match = ".*The userhost.*does not meet.*required pattern"
        with pytest.raises(ValidationError, match=error_match):
            obj = {"userhost": ["NoAtSymbol"]}
            _ = OnlyOn.model_validate_json(json.dumps(obj))

        with pytest.raises(ValidationError, match=error_match):
            obj = {"userhost": ["NoAtSymbol", "valid@entry"]}
            _ = OnlyOn.model_validate_json(json.dumps(obj))

    def test_multiple_invalid_entries(self):
        hostname_list = ["NoAtSymbol", "other invalid@"]
        obj = {"userhost": hostname_list}

        hostname_re_wildcard_str = ".*".join(hostname_list)
        error_match = (
            f".*The userhost.*{hostname_re_wildcard_str}"
            + ".*does not meet.*required pattern"
        )

        with pytest.raises(ValidationError, match=error_match):
            _ = OnlyOn.model_validate_json(json.dumps(obj))


def test_is_allowed():
    """Test the [`dot_vault.config_model.OnlyOn.is_allowed()`] method.

    Also implicitely the [`dot_vault.config_model.OnlyOn.generate_full_allowed_set()`]
    due to its current implementation.

    """
    only_on = OnlyOn(
        username=["emi"], hostname=["yukis-yacht"], userhost=["pommy@pommys-pad"]
    )

    assert only_on.is_allowed(username="emi")
    assert not only_on.is_allowed(hostname="emis-estate")
    assert only_on.is_allowed(username="emi", hostname="emis-estate")

    assert not only_on.is_allowed(username="yuki")
    assert only_on.is_allowed(hostname="yukis-yacht")
    assert only_on.is_allowed(username="yuki", hostname="yukis-yacht")

    assert not only_on.is_allowed(username="pommy")
    assert not only_on.is_allowed(hostname="pommys-pad")
    assert only_on.is_allowed(username="pommy", hostname="pommys-pad")
