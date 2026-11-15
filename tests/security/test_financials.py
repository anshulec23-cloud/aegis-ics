"""Per-device financial profiles (financials.py)."""

import pytest

import financials


def test_role_defaults_and_choices():
    choices = financials.role_choices()
    assert any(c["key"] == "reactor" for c in choices)
    for c in choices:
        assert c["equipment_value"] > 0 and c["downtime_rate_per_hour"] > 0


def test_normalize_fills_from_role_defaults():
    fin = financials.normalize_input({"role": "pump"})
    base = financials.ROLE_DEFAULTS["pump"]
    assert fin["role"] == "pump"
    assert fin["equipment_value"] == base["equipment_value"]
    assert fin["criticality"] == base["criticality"]


def test_normalize_accepts_operator_values():
    fin = financials.normalize_input(
        {
            "role": "turbine",
            "criticality": "TIER-1 CRITICAL",
            "zone": "Hall 3",
            "equipment_value": "1250000",
            "downtime_rate_per_hour": 90000,
            "cleanup_cost": 0,
            "regulatory_exposure": 500000,
        }
    )
    assert fin["equipment_value"] == 1250000.0
    assert fin["cleanup_cost"] == 0.0
    assert fin["zone"] == "Hall 3"


@pytest.mark.parametrize(
    "bad", [{"equipment_value": "abc"}, {"downtime_rate_per_hour": -5}, {"cleanup_cost": "nan"}]
)
def test_normalize_rejects_bad_numbers(bad):
    with pytest.raises(ValueError):
        financials.normalize_input({"role": "pump", **bad})


def test_unknown_role_and_criticality_fall_back():
    fin = financials.normalize_input({"role": "nonsense", "criticality": "SUPER-CRITICAL"})
    assert fin["role"] == "generic"
    assert fin["criticality"] in financials.CRITICALITY_CHOICES


def test_profile_derives_sle_and_regulatory_split():
    class Row:
        device_id = "ESP32_ABCDEF"
        name = "Boiler"
        role = "reactor"
        criticality = "TIER-1 CRITICAL"
        zone = "Unit A"
        equipment_value = 400000.0
        downtime_rate_per_hour = 20000.0
        cleanup_cost = 100000.0
        regulatory_exposure = 300000.0

    p = financials.profile_for("ESP32_ABCDEF", device_row=Row())
    assert p["base_sle"] == 800000.0  # 400k + 100k + 300k
    assert p["epa_fines"] == 150000.0 and p["nerc_cip_fines"] == 150000.0
    assert p["is_custom"] is True
    assert p["name"] == "Boiler"


def test_profile_without_row_uses_generic():
    p = financials.profile_for("ESP32_NEW999", device_row=None)
    assert p["equipment_value"] > 0 and p["is_custom"] is False
