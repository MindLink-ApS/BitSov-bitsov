import atexit

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
AUTO = bd.parse_display_config('driver = "auto"')

PANELS = [
    ((160, 128), "RGB"),
    ((128, 160), "RGB"),
    ((128, 64), "1"),
    ((240, 240), "RGB"),
    ((240, 320), "RGB"),
    ((320, 240), "RGB"),
    ((480, 320), "RGB"),
]


def test_default_profile_is_the_bitcoin_machines_st7735():
    spec = bd.detect_panel(bd.parse_display_config(""), FakeHardware([HDMI, ("/dev/fb1", "fb_ili9486")], spi=True))
    assert (spec.driver, spec.width, spec.height, spec.rotate) == ("st7735", 160, 128, 0)


def test_detect_prefers_panel_framebuffer_over_hdmi():
    spec = bd.detect_panel(AUTO, FakeHardware([HDMI, ("/dev/fb1", "fb_ili9486")], spi=True))
    assert spec.driver == "fbdev" and spec.fb_device == "/dev/fb1"


def test_detect_i2c_oled_at_second_address():
    spec = bd.detect_panel(AUTO, FakeHardware([HDMI], i2c={0x3D: 0x43}))
    assert (spec.driver, spec.i2c_address, spec.width, spec.height) == ("ssd1306", 0x3D, 128, 64)


def test_detect_sh1106_heuristic():
    assert bd.detect_panel(AUTO, FakeHardware(i2c={0x3C: 0x08})).driver == "sh1106"


def test_detect_spi_guess_and_nothing():
    assert bd.detect_panel(AUTO, FakeHardware(spi=True)).driver == "st7789"
    assert bd.detect_panel(AUTO, FakeHardware([HDMI])) is None


def test_config_override_wins_over_detection():
    cfg = bd.DisplayConfig(driver="st7789", width=240, height=320, rotate=1)
    spec = bd.detect_panel(cfg, FakeHardware([("/dev/fb1", "fb_ili9486")], i2c={0x3C: 0}))
    assert (spec.driver, spec.width, spec.height, spec.rotate) == ("st7789", 240, 320, 1)
    assert bd.detect_panel(bd.DisplayConfig(driver="ili9341"), FakeHardware()).width == 320


def test_rgb565_framebuffer_bytes():
    img = Image.new("RGB", (3, 1))
    img.putdata([(255, 0, 0), (0, 255, 0), (0, 0, 255)])
    assert bd.framebuffer_bytes(img, 16) == bytes([0x00, 0xF8, 0xE0, 0x07, 0x1F, 0x00])
    assert bd.framebuffer_bytes(img, 16, red_high=False)[:2] == bytes([0x1F, 0x00])
    assert bd.framebuffer_bytes(img, 32)[:4] == bytes([0, 0, 255, 0])


@pytest.mark.parametrize("size, mode", PANELS)
@pytest.mark.parametrize("chain_aware", [False, True])
def test_every_face_renders_at_every_size(size, mode, chain_aware):
    settings = bd.NodeSettings(readable=True, hosted_by="A rather long box label for wrapping", chain_aware=chain_aware)
    frames = bd.preview_frames(settings)
    assert {face for _, face, _ in frames} == set(bd.FACES)
    for _, face, snap in frames:
        img = bd.render_face(face, size, mode, snap)
        assert img.size == size and img.mode == ("1" if mode == "1" else "RGB")


def _snap(**overrides):
    base = {
        "settings": bd.NodeSettings(),
        "status": bd.NodeStatus(bd.NodeState.OFFLINE),
        "machine": bd.MachineStats(),
        "hostname": "pi",
        "api_port": 3141,
    }
    return bd.Snapshot(**{**base, **overrides})


def test_faces_without_data_are_skipped():
    assert bd.round_faces(bd.FACES, _snap()) == ["bitsov"]


def test_faces_with_data_are_shown_in_configured_order():
    running = bd.NodeStatus(bd.NodeState.RUNNING, block_height=900_000, peers=2, lightning=bd.Lightning.RECEIVE_ONLY)
    snap = _snap(
        settings=bd.NodeSettings(readable=True),
        status=running,
        machine=bd.MachineStats(disk_free_bytes=10**9),
        paid_today=3,
    )
    assert bd.round_faces(bd.FACES, snap) == list(bd.FACES)
    assert bd.round_faces(("machine", "bitsov"), snap) == ["machine", "bitsov"]


def test_live_snapshots_never_carry_a_paid_count(monkeypatch):
    monkeypatch.setattr(bd, "loopback_get", lambda port, path: bd.Probe(None))
    snap = bd.collect_snapshot(bd.parse_display_config(""), bd.Observed())
    assert snap.paid_today is None and "paid" not in bd.round_faces(bd.FACES, snap)
    assert snap.status.state is bd.NodeState.OFFLINE


def test_block_age_is_measured_from_an_observed_tip_change():
    def running(height):
        return bd.NodeStatus(bd.NodeState.RUNNING, block_height=height)

    seen = bd.Observed()
    seen.note(running(100), now=0)
    assert seen.block_age_secs(50) is None
    seen.note(running(100), now=60)
    assert seen.block_age_secs(60) is None
    seen.note(running(101), now=120)
    assert seen.block_age_secs(420) == 300
    seen.note(running(99), now=500)  # reorg or backend swap: age unknown again
    assert seen.block_age_secs(600) is None


def test_lockable_latches_once_the_node_was_seen_locked():
    seen = bd.Observed()
    seen.note(bd.NodeStatus(bd.NodeState.LOCKED), now=0)
    seen.note(bd.NodeStatus(bd.NodeState.RUNNING), now=1)
    assert seen.seen_locked


@pytest.mark.parametrize(
    "secs, text",
    [
        (None, "watching for the next block"),
        (30, "new block just now"),
        (4 * 60 + 10, "last block 4 min ago"),
        (2 * 3600 + 5 * 60, "last block 2 h 5 min ago"),
    ],
)
def test_block_age_text(secs, text):
    assert bd.block_age_text(secs) == text


@pytest.mark.parametrize("n, parts", [(41_200_000_000, ("41.2", "GB")), (512_000_000, ("512", "MB")), (1.2e12, ("1,200", "GB"))])
def test_format_bytes(n, parts):
    assert bd.format_bytes(int(n)) == parts


def test_machine_stats_never_raise(tmp_path):
    stats = bd.read_machine_stats(tmp_path / "absent")
    assert stats.disk_free_bytes is not None and stats.disk_free_bytes >= 0


class FakeDevice:
    size = (160, 128)
    mode = "RGB"

    def __init__(self, log):
        self.log = log
        self.persist = False

    def display(self, image):
        self.log.append("frame")

    def cleanup(self):
        self.log.append("close-keep" if self.persist else "close-clear")


def test_panel_is_reinitialised_before_every_later_round(monkeypatch):
    log = []

    def open_device(spec, cfg):
        log.append(f"open-{spec.driver}")
        return FakeDevice(log)

    status = bd.NodeStatus(bd.NodeState.RUNNING, block_height=1)
    monkeypatch.setattr(bd, "open_device", open_device)
    monkeypatch.setattr(bd, "collect_snapshot", lambda cfg, seen: _snap(status=status))
    bd.run(bd.parse_display_config(""), FakeHardware(), sleep=lambda _s: None, rounds=3)
    round_ = ["frame", "frame"]  # bitsov + bitcoin; the rest have no data
    assert log == (
        ["open-st7735", *round_]
        + ["close-keep", "open-st7735", *round_]
        + ["close-keep", "open-st7735", *round_]
        + ["close-clear"]
    )


def test_failed_reinit_retries_without_killing_the_service(monkeypatch):
    opens = []

    def open_device(spec, cfg):
        opens.append(1)
        if len(opens) == 2:
            raise OSError("spi glitch")
        return FakeDevice([])

    monkeypatch.setattr(bd, "open_device", open_device)
    monkeypatch.setattr(bd, "collect_snapshot", lambda cfg, seen: _snap())
    bd.run(bd.parse_display_config(""), FakeHardware(), sleep=lambda _s: None, rounds=2)
    assert len(opens) == 3


def test_luma_devices_register_no_atexit_hook(monkeypatch):
    from luma.core.device import dummy

    hooks = []
    monkeypatch.setattr(atexit, "register", lambda fn, *a, **k: hooks.append(fn))
    with bd.without_luma_atexit():
        dummy(width=160, height=128, mode="RGB")
    assert hooks == []
    dummy(width=160, height=128, mode="RGB")
    assert len(hooks) == 1


def test_previews_are_160x128_for_every_face(tmp_path):
    (tmp_path / "stale.png").write_bytes(b"")
    written = bd.write_previews(tmp_path, bd.NodeSettings(readable=True))
    faces = [p for p in written if p.name != "overview.png"]
    assert len(faces) == len(bd.preview_frames(bd.NodeSettings(readable=True)))
    assert all(Image.open(p).size == (160, 128) for p in faces)
    assert not (tmp_path / "stale.png").exists()
