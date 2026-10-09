import pytest

import bitsov_display as bd


@pytest.mark.parametrize(
    "base, admission, expected",
    [
        (0, 0, 1000),
        (1, 0, 1000),
        (10, 0, 1000),
        (999, 0, 1000),
        (1000, 0, 1000),
        (1500, 0, 1500),
        (10_000, 0, 10_000),
        (1000, 2000, 2000),
        (5000, 2000, 5000),
        (10, 50, 1000),
    ],
)
def test_floor_matches_price_with_floor_msat(base, admission, expected):
    assert bd.floored_price_msat(base, admission) == expected


def test_floor_never_below_one_sat():
    for base in range(0, 3001, 7):
        for admission in (0, 1, 999, 1000, 2500):
            assert bd.floored_price_msat(base, admission) >= 1000


@pytest.mark.parametrize(
    "msat, text",
    [
        (1000, "1 sat"),
        (1500, "1.5 sats"),
        (1001, "1.001 sats"),
        (10_000, "10 sats"),
        (10_000_000, "10,000 sats"),
    ],
)
def test_format_sats(msat, text):
    assert bd.format_sats(msat) == text


def _shown(settings):
    return {label: bd.format_sats(msat) for label, msat in bd.price_rows(settings)}


def test_price_face_shows_message_call_and_page():
    assert [label for label, _ in bd.price_rows(bd.NodeSettings(readable=True))] == ["Message", "Call", "Page"]


def test_default_price_rows_never_show_zero():
    rows = _shown(bd.NodeSettings(readable=True))
    assert rows["Message"] == "1 sat"  # chat_msat = 10 is floored
    assert rows["Call"] == "10 sats"
    assert rows["Page"] == "1 sat"
    assert all(not v.startswith("0") for v in rows.values())


def test_zero_prices_from_config_still_floor():
    lines = ["[pricing]"] + [f"{key} = 0" for key, _, _ in bd.PRICE_TABLE]
    settings = bd.node_settings_from_values(bd.allowed_node_values(lines))
    assert all(v == "1 sat" for v in _shown(settings).values())


def test_admission_floor_applies_to_every_row():
    settings = bd.node_settings_from_values(
        bd.allowed_node_values(["[payment_gate]", "min_admission_cost_msat = 2000"])
    )
    rows = _shown(settings)
    assert rows["Message"] == "2 sats"
    assert rows["Call"] == "10 sats"
    assert rows["Page"] == "2 sats"
