import json
import re

import pytest
from pydantic import ValidationError

from dot_vault.config_model import ONLYON_USERHOST_PATTERN, OnlyOn


def test_only_on_userhost_pattern():
    pattern = re.compile(ONLYON_USERHOST_PATTERN)

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
