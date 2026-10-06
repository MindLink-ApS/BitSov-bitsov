import pytest
from PIL import Image

import bitsov_display as bd


class FakeHardware(bd.Hardware):
    def __init__(self, fbs=(), i2c=None, spi=False):
        self._fbs = list(fbs)
        self._i2c = i2c or {}
        self._spi = spi

    def framebuffers(self):
        return self._fbs

    def i2c_status(self, port, address):
        return self._i2c.get(address)

    def spidev(self, port, device):
        return self._spi


HDMI = ("/dev/fb0", "vc4drmfb")


def test_detect_prefers_panel_framebuffer_over_hdmi():
    spec = bd.detect_panel(bd.DisplayConfig(), FakeHardware([HDMI, ("/dev/fb1", "fb_ili9486")], spi=True))
    assert spec.driver == "fbdev" and spec.fb_device == "/dev/fb1"


def test_detect_i2c_oled_at_second_address():
    spec = bd.detect_panel(bd.DisplayConfig(), FakeHardware([HDMI], i2c={0x3D: 0x43}))
    assert (spec.driver, spec.i2c_address, spec.width, spec.height) == ("ssd1306", 0x3D, 128, 64)


def test_detect_sh1106_heuristic():
    assert bd.detect_panel(bd.DisplayConfig(), FakeHardware(i2c={0x3C: 0x08})).driver == "sh1106"


def test_detect_spi_guess_and_nothing():
    assert bd.detect_panel(bd.DisplayConfig(), FakeHardware(spi=True)).driver == "st7789"
    assert bd.detect_panel(bd.DisplayConfig(), FakeHardware([HDMI])) is None


def test_config_override_wins_over_detection():
    cfg = bd.DisplayConfig(driver="st7789", width=240, height=320, rotate=1)
    spec = bd.detect_panel(cfg, FakeHardware([("/dev/fb1", "fb_ili9486")], i2c={0x3C: 0}))
    assert (spec.driver, spec.width, spec.height, spec.rotate) == ("st7789", 240, 320, 1)
    assert bd.detect_panel(bd.DisplayConfig(driver="ili9341"), FakeHardware()).width == 320


def test_pick_lan_ip_prefers_private_wired_and_skips_virtual():
    addrs = [
        ("lo", "127.0.0.1"),
        ("tailscale0", "100.101.102.103"),
        ("docker0", "172.17.0.1"),
        ("wlan0", "192.168.1.60"),
        ("eth0", "192.168.1.42"),
    ]
    assert bd.pick_lan_ip(addrs) == "192.168.1.42"
    assert bd.pick_lan_ip(addrs[:4]) == "192.168.1.60"
    assert bd.pick_lan_ip([("lo", "127.0.0.1"), ("eth0", "169.254.3.4")]) is None


def test_rgb565_framebuffer_bytes():
    img = Image.new("RGB", (3, 1))
    img.putdata([(255, 0, 0), (0, 255, 0), (0, 0, 255)])
    assert bd.framebuffer_bytes(img, 16) == bytes([0x00, 0xF8, 0xE0, 0x07, 0x1F, 0x00])
    assert bd.framebuffer_bytes(img, 16, red_high=False)[:2] == bytes([0x1F, 0x00])
    assert bd.framebuffer_bytes(img, 32)[:4] == bytes([0, 0, 255, 0])


@pytest.mark.parametrize("name, size, mode", bd.PREVIEW_PROFILES)
@pytest.mark.parametrize("chain_aware", [False, True])
def test_every_page_renders_at_every_size(name, size, mode, chain_aware):
    settings = bd.NodeSettings(readable=True, hosted_by="A rather long box label for wrapping", chain_aware=chain_aware)
    snaps = bd.preview_snapshots(settings)
    pages = bd.build_pages(bd.SCREENS, size, settings)
    priced = [p for p in pages if p.screen == "prices"]
    _, per_page = bd.price_pages(size, settings)
    assert sum(len(bd.PRICE_TABLE[p.index * per_page : (p.index + 1) * per_page]) for p in priced) == len(
        bd.PRICE_TABLE
    )
    for page in pages:
        for snap in snaps.values():
            img = bd.render_page(page, size, mode, snap)
            assert img.size == size and img.mode == ("1" if mode == "1" else "RGB")


def test_unreadable_config_renders_single_price_notice():
    settings = bd.NodeSettings()
    pages = bd.build_pages(bd.SCREENS, (128, 64), settings)
    assert [p.screen for p in pages] == list(bd.SCREENS)
    snap = bd.Snapshot(settings, bd.NodeStatus(bd.NodeState.OFFLINE), None, "pi", 3141)
    bd.render_page(pages[2], (128, 64), "1", snap)
