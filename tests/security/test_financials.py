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


def test_legacy_inline_financials_migrate_to_device_financials(tmp_path, monkeypatch):
    """v2.5-era `devices` rows carried the money inline.

    Upgrading must move those profiles into `device_financials` intact rather than lose them,
    must skip devices that never had a profile, and must be safe to run twice.
    """
    import sqlite3

    import database

    db_path = tmp_path / "legacy.db"
    con = sqlite3.connect(db_path)
    con.executescript(
        """
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY, device_id VARCHAR(50) UNIQUE NOT NULL,
            name VARCHAR(80), status VARCHAR(16), role VARCHAR(32),
            criticality VARCHAR(20), zone VARCHAR(80), equipment_value FLOAT,
            downtime_rate_per_hour FLOAT, cleanup_cost FLOAT, regulatory_exposure FLOAT);
        INSERT INTO devices (device_id, name, status, role, criticality, zone,
            equipment_value, downtime_rate_per_hour, cleanup_cost, regulatory_exposure)
            VALUES ('ESP32_LEGACY', 'Reactor 1', 'approved', 'reactor', 'TIER-1 CRITICAL',
                    'Unit A', 450000.0, 22500.0, 120000.0, 400000.0);
        INSERT INTO devices (device_id, name, status) VALUES ('ESP32_NOFIN', 'Pump', 'approved');
        """
    )
    con.commit()
    con.close()

    monkeypatch.setattr(database, "DATABASE_URL", f"sqlite:///{db_path}")
    database.migrate_sqlite_schema()

    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            "SELECT device_id, role, criticality, zone, equipment_value, "
            "downtime_rate_per_hour, cleanup_cost, regulatory_exposure FROM device_financials"
        ).fetchall()
        # only the device that actually had a profile moves, and every field survives
        assert rows == [
            ("ESP32_LEGACY", "reactor", "TIER-1 CRITICAL", "Unit A",
             450000.0, 22500.0, 120000.0, 400000.0)
        ]
        database.migrate_sqlite_schema()  # re-running must not duplicate
        assert con.execute("SELECT COUNT(*) FROM device_financials").fetchone()[0] == 1
    finally:
        con.close()
