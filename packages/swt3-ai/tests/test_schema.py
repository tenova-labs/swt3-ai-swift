"""Tests for SWT3 YAML schema validator."""

from swt3_ai.schema import validate_schema


class TestSchemaValidator:
    def test_valid_config_passes(self) -> None:
        result = validate_schema({
            "api_key": "axm_test",
            "tenant_id": "TEST",
            "clearing_level": 2,
            "trust_mesh": {"mode": "strict", "min_trust_level": 2},
            "policy": {"require_signing": True},
        })
        assert result.valid is True
        assert len(result.errors) == 0

    def test_unknown_top_level_key(self) -> None:
        result = validate_schema({
            "api_key": "axm_test",
            "bogus_field": True,
        })
        assert result.valid is False
        assert result.errors[0].path == "bogus_field"
        assert "unknown top-level key" in result.errors[0].message

    def test_wrong_type_clearing_level(self) -> None:
        result = validate_schema({
            "api_key": "axm_test",
            "clearing_level": "high",
        })
        assert result.valid is False
        assert result.errors[0].path == "clearing_level"

    def test_invalid_enum_value(self) -> None:
        result = validate_schema({
            "api_key": "axm_test",
            "trust_mesh": {"mode": "aggressive"},
        })
        assert result.valid is False
        assert result.errors[0].path == "trust_mesh.mode"

    def test_wrong_type_in_section(self) -> None:
        result = validate_schema({
            "api_key": "axm_test",
            "policy": {"require_signing": "yes"},
        })
        assert result.valid is False
        assert result.errors[0].path == "policy.require_signing"
        assert "expected boolean" in result.errors[0].message

    def test_multiple_errors_accumulated(self) -> None:
        result = validate_schema({
            "bogus1": True,
            "bogus2": True,
            "clearing_level": 99,
            "trust_mesh": {"mode": "invalid", "bad_key": True},
        })
        assert result.valid is False
        assert len(result.errors) >= 4
