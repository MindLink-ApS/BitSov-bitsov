import pytest

import bitsov_display as bd

SECRET = "NOT-A-REAL-SECRET-display-must-never-parse-this"

NODE_TOML = f'''
tier = "full"

[node]
hosted_by = "Rasmus's Pi"  # shown on the host screen

[identity]
mnemonic_file = "/home/node/.local/share/konsensus/identity/mnemonic.enc"
hosted = false

[api]
listen_addr = "127.0.0.1:4242"
jwt_secret = "{SECRET}"

[lightning]
backend = "lnbits"
api_key = "{SECRET}"

[pricing]
mode = "chain_aware"
chat_msat = 2_500
call_msat = 20000
category_fee_targets = {{ files_media = 25 }}

[pricing.category_fee_targets_extra]
chat_msat = 999999

[payment_gate]
min_admission_cost_msat = 1500

[[peers]]
node_id = "abcdef1234567890"
chat_msat = 777

[web]
site_name = """
[pricing]
chat_msat = 1
"""
'''


def test_node_config_keeps_only_allow_listed_keys():
    values = bd.allowed_node_values(NODE_TOML.splitlines())
    assert set(values) <= bd.NODE_KEYS
    assert SECRET not in repr(values)
    assert values == {
        "node.hosted_by": "Rasmus's Pi",
        "api.listen_addr": "127.0.0.1:4242",
        "pricing.mode": "chain_aware",
        "pricing.chat_msat": 2500,
        "pricing.call_msat": 20000,
        "payment_gate.min_admission_cost_msat": 1500,
    }


def test_node_settings_from_file(tmp_path):
    path = tmp_path / "konsensus.toml"
    path.write_text(NODE_TOML)
    s = bd.read_node_settings(path)
    assert s.readable
    assert s.api_port == 4242
    assert s.hosted_by == "Rasmus's Pi"
    assert s.chain_aware
    assert s.min_admission_cost_msat == 1500
    assert s.prices_msat["chat_msat"] == 2500
    assert s.prices_msat["call_msat"] == 20000
    assert s.prices_msat["longform_msat"] == 50  # node default


def test_missing_or_unreadable_node_config_is_not_fatal(tmp_path):
    assert bd.read_node_settings(tmp_path / "absent.toml").readable is False
    assert bd.read_node_settings(None).readable is False


def test_empty_node_config_uses_node_defaults():
    s = bd.node_settings_from_values(bd.allowed_node_values([]))
    assert s.readable and s.api_port == 3141 and s.hosted_by is None
    assert s.prices_msat == bd.DEFAULT_PRICES_MSAT
    assert s.min_admission_cost_msat == 0 and not s.chain_aware


def test_root_dotted_keys_and_quoted_headers():
    values = bd.allowed_node_values(["pricing.chat_msat = 3000", '[ "api" ]', 'listen_addr = "[::1]:3999"'])
    assert values == {"pricing.chat_msat": 3000, "api.listen_addr": "[::1]:3999"}


@pytest.mark.parametrize(
    "addr, port",
    [
        ("127.0.0.1:3141", 3141),
        ("0.0.0.0:8080", 8080),
        ("[::1]:3142", 3142),
        ("127.0.0.1", None),
        ("127.0.0.1:0", None),
        ("127.0.0.1:70000", None),
        (3141, None),
    ],
)
def test_parse_listen_port(addr, port):
    assert bd.parse_listen_port(addr) == port


@pytest.mark.parametrize("bad", ["", " padded", "a\u202eb", "x" * 65, "line\nbreak", "zero\u200bwidth", 7])
def test_invalid_hosted_by_is_not_shown(bad):
    assert bd.valid_hosted_by(bad) is None


@pytest.mark.parametrize("bad", ['"10"', "-5", "true", "1.5", "18446744073709551616"])
def test_invalid_price_falls_back_to_node_default(bad):
    s = bd.node_settings_from_values(bd.allowed_node_values(["[pricing]", f"chat_msat = {bad}"]))
    assert s.prices_msat["chat_msat"] == 10


def test_display_config_defaults():
    assert bd.parse_display_config("") == bd.DisplayConfig()


def test_display_config_full():
    cfg = bd.parse_display_config(
        """
        driver = "sh1106"
        width = 128
        height = 64
        rotate = 2
        i2c_address = 0x3D
        gpio_rst = -1
        gpio_backlight = 12
        backlight_active_low = true
        node_config = "/home/node/.local/share/konsensus/konsensus.toml"
        api_port = 4000
        interval_secs = 10
        screens = ["status", "prices"]
        """
    )
    assert cfg.driver == "sh1106" and (cfg.width, cfg.height, cfg.rotate) == (128, 64, 2)
    assert cfg.i2c_address == 0x3D and cfg.gpio_rst is None and cfg.gpio_backlight == 12
    assert cfg.backlight_active_low and cfg.api_port == 4000 and cfg.interval_secs == 10.0
    assert cfg.screens == ("status", "prices")


@pytest.mark.parametrize(
    "text, message",
    [
        ('driver = "epaper"', "driver must be one of"),
        ("rotate = 4", "rotate"),
        ("width = 240", "set together"),
        ("i2c_address = 0x80", "i2c_address"),
        ("gpio_dc = -1", "gpio_dc"),
        ("spi_speed_hz = 100", "spi_speed_hz"),
        ('node_config = "relative.toml"', "absolute path"),
        ("interval_secs = 1", "interval_secs"),
        ('screens = ["status", "status"]', "screens"),
        ('screens = ["balance"]', "screens"),
        ("screens = []", "screens"),
        ("api_port = true", "api_port"),
        ("jwt_secret = 'x'", "unknown display config keys: jwt_secret"),
        ("driver = ", "not valid TOML"),
    ],
)
def test_display_config_rejects(text, message):
    with pytest.raises(bd.ConfigError, match=message):
        bd.parse_display_config(text)


def test_missing_display_config_means_auto(tmp_path):
    assert bd.load_display_config(tmp_path / "display.toml") == bd.DisplayConfig()
