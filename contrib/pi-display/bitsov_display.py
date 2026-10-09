#!/usr/bin/env python3
"""BitSov front display for a Raspberry Pi home node.

Rotates six faces on the case's small panel: the BitSov node state, the node's
own price per act, paid acts today, Bitcoin, Lightning and the machine. A face
whose data is unavailable is skipped for that round.

It is deliberately blind to everything that matters for custody. It talks only
to 127.0.0.1, keeps only an allow-list of fields from those answers, and reads
konsensus.toml through a line filter that discards every line outside that
allow-list before anything is parsed. It never touches the seed, mnemonic,
password, pairing links, tickets, tokens or balances, and shows no fiat price.
See README.md.
"""

from __future__ import annotations

import argparse
import contextlib
import functools
import glob
import http.client
import json
import logging
import os
import re
import signal
import socket
import struct
import sys
import time
import tomllib
import types
import unicodedata
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from pathlib import Path
from collections.abc import Callable, Iterable

from PIL import Image, ImageChops, ImageDraw, ImageFont

log = logging.getLogger("bitsov-display")

LOOPBACK = "127.0.0.1"
DEFAULT_API_PORT = 3141
DEFAULT_CONFIG_PATH = Path("/etc/bitsov-display/display.toml")
NODE_CONFIG_CANDIDATES = (
    "/home/*/.local/share/konsensus/konsensus.toml",
    "/var/lib/konsensus/konsensus.toml",
)
MAX_NODE_CONFIG_BYTES = 1 << 20
MAX_HTTP_BODY = 16 * 1024
HTTP_TIMEOUT_SECS = 1.5

# konsensus_core::gate::price_with_floor_msat: every kind costs at least 1 sat.
MIN_PAYABLE_MSAT = 1_000

# (config key, label) in display order, with the node's defaults from
# crates/konsensus-node/src/config.rs (default_*_msat). Keep in sync.
PRICE_TABLE: tuple[tuple[str, str, int], ...] = (
    ("chat_msat", "Message", 10),
    ("call_msat", "Call", 10_000),
    ("web_content_msat", "Page", 1_000),
)
DEFAULT_PRICES_MSAT = {key: default for key, _, default in PRICE_TABLE}

# The only konsensus.toml keys this program ever parses.
NODE_KEYS = frozenset(
    {
        "node.hosted_by",
        "api.listen_addr",
        "pricing.mode",
        "payment_gate.min_admission_cost_msat",
    }
    | {f"pricing.{key}" for key, _, _ in PRICE_TABLE}
)

# The only fields kept from loopback API answers. /api/v1/health is the
# node's public, redacted health: no balances, keys or peer IDs.
PROBE_FIELDS = (
    "state",
    "uptime_secs",
    "hosted_by",
    "block_height",
    "connected_peers",
    "lightning_available",
    "lightning_payment_capable",
)

FACES = ("bitsov", "price", "paid", "bitcoin", "lightning", "machine")
I2C_DRIVERS = ("ssd1306", "sh1106")
SPI_DRIVERS = ("st7735", "st7789", "ili9341")
DRIVERS = ("auto", *I2C_DRIVERS, *SPI_DRIVERS, "fbdev")
DEFAULT_SIZES = {
    "ssd1306": (128, 64),
    "sh1106": (128, 64),
    "st7735": (160, 128),
    "st7789": (240, 240),
    "ili9341": (320, 240),
}
OLED_ADDRESSES = (0x3C, 0x3D)
# luma.core.interface.serial.spi refuses any other bus speed.
SPI_SPEEDS_HZ = tuple(
    int(mhz * 1_000_000) for mhz in (0.5, 1, 2, 4, 8, 16, 20, 24, 28, 32, 36, 40, 44, 48, 50, 52)
)

PROFILES: dict[str, dict[str, object]] = {
    # Bitcoin Machines case: ST7735 1.8" on SPI0 CE0, backlight active high.
    "bitcoin-machines": {
        "driver": "st7735",
        "width": 160,
        "height": 128,
        "spi_speed_hz": 8_000_000,
        "gpio_dc": 24,
        "gpio_rst": 25,
        "gpio_backlight": 18,
        "backlight_active_low": False,
    },
}
DEFAULT_PROFILE = "bitcoin-machines"


class ConfigError(ValueError):
    """display.toml is invalid; the service refuses to guess."""


# --------------------------------------------------------------------------
# display.toml
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class DisplayConfig:
    """Generic defaults. parse_display_config applies a profile unless `driver` is set."""

    profile: str | None = None
    driver: str = "auto"
    width: int | None = None
    height: int | None = None
    rotate: int = 0
    i2c_port: int = 1
    i2c_address: int | None = None
    spi_port: int = 0
    spi_device: int = 0
    spi_speed_hz: int = 32_000_000
    gpio_dc: int = 24
    gpio_rst: int | None = 25
    gpio_backlight: int | None = 18
    backlight_active_low: bool = False
    fb_device: str | None = None
    node_config: str | None = None
    api_port: int | None = None
    remote_unlock: bool = False
    interval_secs: float = 8.0
    faces: tuple[str, ...] = FACES


def _int(name: str, value: object, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise ConfigError(f"{name} must be an integer in {lo}..{hi}")
    return value


def _pin(name: str, value: object) -> int | None:
    pin = _int(name, value, -1, 27)
    return None if pin == -1 else pin


def _bool(name: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{name} must be true or false")
    return value


def parse_display_config(text: str) -> DisplayConfig:
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"display config is not valid TOML: {e}") from None
    known = {f.name for f in DisplayConfig.__dataclass_fields__.values()}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ConfigError(f"unknown display config keys: {', '.join(unknown)}")
    if "profile" in raw and "driver" in raw:
        raise ConfigError("set either profile or driver, not both")
    profile = raw.get("profile", DEFAULT_PROFILE)
    if profile not in PROFILES:
        raise ConfigError(f"profile must be one of: {', '.join(PROFILES)}")

    out: dict[str, object] = {}
    if "driver" in raw:
        if raw["driver"] not in DRIVERS:
            raise ConfigError(f"driver must be one of: {', '.join(DRIVERS)}")
        out["driver"] = raw["driver"]
    for name in ("width", "height"):
        if name in raw:
            out[name] = _int(name, raw[name], 8, 4096)
    if ("width" in out) != ("height" in out):
        raise ConfigError("width and height must be set together")
    if "rotate" in raw:
        out["rotate"] = _int("rotate", raw["rotate"], 0, 3)
    if "i2c_port" in raw:
        out["i2c_port"] = _int("i2c_port", raw["i2c_port"], 0, 255)
    if "i2c_address" in raw:
        out["i2c_address"] = _int("i2c_address", raw["i2c_address"], 0x03, 0x77)
    for name in ("spi_port", "spi_device"):
        if name in raw:
            out[name] = _int(name, raw[name], 0, 15)
    if "spi_speed_hz" in raw:
        if raw["spi_speed_hz"] not in SPI_SPEEDS_HZ or isinstance(raw["spi_speed_hz"], bool):
            raise ConfigError(f"spi_speed_hz must be one of: {', '.join(map(str, SPI_SPEEDS_HZ))}")
        out["spi_speed_hz"] = int(raw["spi_speed_hz"])
    if "gpio_dc" in raw:
        out["gpio_dc"] = _int("gpio_dc", raw["gpio_dc"], 0, 27)
    for name in ("gpio_rst", "gpio_backlight"):
        if name in raw:
            out[name] = _pin(name, raw[name])
    for name in ("backlight_active_low", "remote_unlock"):
        if name in raw:
            out[name] = _bool(name, raw[name])
    for name in ("fb_device", "node_config"):
        if name in raw:
            value = raw[name]
            if not isinstance(value, str) or not value.startswith("/"):
                raise ConfigError(f"{name} must be an absolute path")
            out[name] = value
    if "api_port" in raw:
        out["api_port"] = _int("api_port", raw["api_port"], 1, 65535)
    if "interval_secs" in raw:
        value = raw["interval_secs"]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 2 <= value <= 300:
            raise ConfigError("interval_secs must be a number in 2..300")
        out["interval_secs"] = float(value)
    if "faces" in raw:
        faces = raw["faces"]
        if (
            not isinstance(faces, list)
            or not faces
            or any(f not in FACES for f in faces)
            or len(set(faces)) != len(faces)
        ):
            raise ConfigError(f"faces must be a non-empty list drawn from: {', '.join(FACES)}")
        out["faces"] = tuple(faces)
    base = {} if "driver" in raw else {"profile": profile, **PROFILES[profile]}
    return DisplayConfig(**{**base, **out})


def load_display_config(path: Path) -> DisplayConfig:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        log.info("no %s; using the %s profile", path, DEFAULT_PROFILE)
        return parse_display_config("")
    except OSError as e:
        raise ConfigError(f"cannot read {path}: {e.strerror}") from None
    return parse_display_config(text)


# --------------------------------------------------------------------------
# konsensus.toml (read-only, allow-listed)
# --------------------------------------------------------------------------

_HEADER = re.compile(r"^\[(\[)?\s*([A-Za-z0-9_\-.\"' ]+?)\s*\]\]?\s*(?:#.*)?$")
_KEYVAL = re.compile(r"^([A-Za-z0-9_\-.\"' ]+?)\s*=\s*(.*)$")


def _dotted(name: str) -> str:
    return ".".join(part.strip().strip("\"'").strip() for part in name.split("."))


def allowed_node_values(lines: Iterable[str]) -> dict[str, object]:
    """Return values for NODE_KEYS only.

    Each line is classified and dropped unless its full dotted key is in the
    allow-list; only surviving single-line values reach the TOML parser. Secrets
    such as [api].jwt_secret or [lightning] keys are never parsed or retained.
    """
    values: dict[str, object] = {}
    table = ""
    open_quote: str | None = None
    for raw in lines:
        line = raw.strip()
        if open_quote:
            if line.count(open_quote) % 2:
                open_quote = None
            continue
        if not line or line.startswith("#"):
            continue
        header = _HEADER.match(line)
        if header:
            table = _dotted(header.group(2)) + ("[]" if header.group(1) else "")
            continue
        pair = _KEYVAL.match(line)
        if not pair:
            continue
        rhs = pair.group(2)
        for quote in ('"""', "'''"):
            if rhs.count(quote) % 2:
                open_quote = quote
        key = _dotted(pair.group(1))
        full = f"{table}.{key}" if table else key
        if open_quote or full not in NODE_KEYS:
            continue
        try:
            values[full] = tomllib.loads(f"v = {rhs}")["v"]
        except tomllib.TOMLDecodeError:
            continue
    return values


_INVISIBLE = (
    {0x00AD, 0x061C, 0x180E, 0xFEFF}
    | set(range(0x200B, 0x2010))
    | set(range(0x2028, 0x202F))
    | set(range(0x2060, 0x2065))
    | set(range(0x2066, 0x206A))
    | set(range(0xFFF9, 0xFFFC))
)


def valid_hosted_by(label: object) -> str | None:
    """Mirror of NodeDisplayConfig::validate; invalid labels are not shown."""
    if not isinstance(label, str) or not label.strip() or label.strip() != label:
        return None
    if len(label) > 64:
        return None
    if any(unicodedata.category(c) == "Cc" or ord(c) in _INVISIBLE for c in label):
        return None
    return label


def _u64(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << 64:
        return None
    return value


def parse_listen_port(addr: object) -> int | None:
    if not isinstance(addr, str):
        return None
    _, sep, port = addr.rpartition(":")
    if not sep or not port.isdigit():
        return None
    value = int(port)
    return value if 1 <= value <= 65535 else None


@dataclass(frozen=True)
class NodeSettings:
    readable: bool = False
    api_port: int = DEFAULT_API_PORT
    hosted_by: str | None = None
    prices_msat: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_PRICES_MSAT))
    min_admission_cost_msat: int = 0
    chain_aware: bool = False


def node_settings_from_values(values: dict[str, object]) -> NodeSettings:
    prices = {}
    for key, _, default in PRICE_TABLE:
        value = _u64(values.get(f"pricing.{key}"))
        prices[key] = default if value is None else value
    return NodeSettings(
        readable=True,
        api_port=parse_listen_port(values.get("api.listen_addr")) or DEFAULT_API_PORT,
        hosted_by=valid_hosted_by(values.get("node.hosted_by")),
        prices_msat=prices,
        min_admission_cost_msat=_u64(values.get("payment_gate.min_admission_cost_msat")) or 0,
        chain_aware=values.get("pricing.mode") == "chain_aware",
    )


def resolve_node_config(configured: str | None) -> Path | None:
    if configured:
        return Path(configured)
    found = sorted({p for pattern in NODE_CONFIG_CANDIDATES for p in glob.glob(pattern)})
    return Path(found[0]) if len(found) == 1 else None


def read_node_settings(path: Path | None) -> NodeSettings:
    if path is None:
        return NodeSettings()
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            lines = f.read(MAX_NODE_CONFIG_BYTES).splitlines()
    except OSError:
        return NodeSettings()
    return node_settings_from_values(allowed_node_values(lines))


# --------------------------------------------------------------------------
# Price per act
# --------------------------------------------------------------------------


def floored_price_msat(base_msat: int, min_admission_cost_msat: int = 0) -> int:
    """konsensus_core::gate::price_with_floor_msat for an undiscounted stranger."""
    return max(base_msat, min_admission_cost_msat, MIN_PAYABLE_MSAT)


def sats_parts(msat: int) -> tuple[str, str]:
    sats = Decimal(msat) / 1000
    number = f"{sats:,.3f}".rstrip("0").rstrip(".")
    return number, "sat" if sats == 1 else "sats"


def format_sats(msat: int) -> str:
    return " ".join(sats_parts(msat))


def price_rows(settings: NodeSettings) -> list[tuple[str, int]]:
    """(label, floored msat) per shown kind."""
    return [
        (label, floored_price_msat(settings.prices_msat[key], settings.min_admission_cost_msat))
        for key, label, _ in PRICE_TABLE
    ]


# --------------------------------------------------------------------------
# Node state over loopback
# --------------------------------------------------------------------------


class NodeState(Enum):
    RUNNING = "running"
    LOCKED = "locked"
    SETUP = "setup"
    OFFLINE = "offline"


class Lightning(Enum):
    READY = "ready to pay"
    RECEIVE_ONLY = "receive only"
    DOWN = "backend unreachable"


@dataclass(frozen=True)
class Probe:
    """One loopback answer. status None means nothing answered."""

    status: int | None
    fields: dict[str, object] = field(default_factory=dict)
    plain_ok: bool = False


@dataclass(frozen=True)
class NodeStatus:
    state: NodeState
    uptime_secs: int | None = None
    hosted_by: str | None = None
    block_height: int | None = None
    peers: int | None = None
    lightning: Lightning | None = None


def probe_from_body(status: int, body: bytes) -> Probe:
    text = body.decode("utf-8", errors="replace").strip()
    try:
        payload = json.loads(text) if text else None
    except ValueError:
        payload = None
    fields = {k: payload[k] for k in PROBE_FIELDS if isinstance(payload, dict) and k in payload}
    return Probe(status, fields, plain_ok=text == "ok")


def loopback_get(port: int, path: str, timeout: float = HTTP_TIMEOUT_SECS) -> Probe:
    """GET http://127.0.0.1:<port><path>. No proxies, no redirects, no other host."""
    if not path.startswith("/") or not 1 <= port <= 65535:
        raise ValueError("loopback_get needs an absolute path and a valid port")
    conn = http.client.HTTPConnection(LOOPBACK, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Accept": "application/json", "Connection": "close"})
        response = conn.getresponse()
        return probe_from_body(response.status, response.read(MAX_HTTP_BODY))
    except (OSError, http.client.HTTPException):
        return Probe(None)
    finally:
        conn.close()


def _ok_fields(probe: Probe | None) -> dict[str, object]:
    return probe.fields if probe is not None and probe.status == 200 else {}


def _lightning(fields: dict[str, object]) -> Lightning | None:
    available, capable = fields.get("lightning_available"), fields.get("lightning_payment_capable")
    if not isinstance(available, bool) or not isinstance(capable, bool):
        return None
    if not available:
        return Lightning.DOWN
    return Lightning.READY if capable else Lightning.RECEIVE_ONLY


def map_state(lock: Probe, livez: Probe | None = None, health: Probe | None = None) -> NodeStatus:
    """Map loopback answers to what the panel shows.

    Locked router: /api/v1/node/lock answers {"state": "locked"}.
    Bootstrap (first run): /livez answers plain "ok", no lock route.
    Live node: no lock route; the public /api/v1/health carries chain height,
    peer count and Lightning readiness, and uptime when /livez is off.
    """
    hosted_by = None
    for probe in (lock, livez, health):
        if hosted_by is None:
            hosted_by = valid_hosted_by(_ok_fields(probe).get("hosted_by"))
    if lock.status is None and (livez is None or livez.status is None):
        return NodeStatus(NodeState.OFFLINE)
    if lock.status == 200 and lock.fields.get("state") == "locked":
        return NodeStatus(NodeState.LOCKED, hosted_by=hosted_by)
    if livez is not None and livez.status == 200 and livez.plain_ok and lock.status == 404:
        return NodeStatus(NodeState.SETUP)
    live, public = _ok_fields(livez), _ok_fields(health)
    uptime = _u64(live.get("uptime_secs"))
    return NodeStatus(
        NodeState.RUNNING,
        _u64(public.get("uptime_secs")) if uptime is None else uptime,
        hosted_by,
        block_height=_u64(public.get("block_height")),
        peers=_u64(public.get("connected_peers")),
        lightning=_lightning(public),
    )


def probe_node(get: Callable[[str], Probe]) -> NodeStatus:
    lock = get("/api/v1/node/lock")
    if lock.status is None or (lock.status == 200 and lock.fields.get("state") == "locked"):
        return map_state(lock)
    livez = get("/livez")
    if livez.plain_ok and lock.status == 404:
        return map_state(lock, livez)
    return map_state(lock, livez, get("/api/v1/health"))


def format_uptime(secs: int) -> str:
    days, rest = divmod(secs, 86_400)
    hours, rest = divmod(rest, 3_600)
    minutes, seconds = divmod(rest, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m"
    return f"{seconds}s"


# --------------------------------------------------------------------------
# The machine itself (local files only)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class MachineStats:
    cpu_temp_c: float | None = None
    disk_free_bytes: int | None = None
    uptime_secs: int | None = None

    @property
    def any(self) -> bool:
        return any(v is not None for v in (self.cpu_temp_c, self.disk_free_bytes, self.uptime_secs))


def read_machine_stats(disk_path: Path | None = None) -> MachineStats:
    """CPU temperature, free space where the node keeps its data, OS uptime."""
    temp = None
    try:
        value = int(Path("/sys/class/thermal/thermal_zone0/temp").read_text().strip()) / 1000
        temp = value if -40 <= value <= 150 else None
    except (OSError, ValueError):
        pass
    try:
        st = os.statvfs(disk_path if disk_path is not None and disk_path.exists() else "/")
        disk = st.f_bavail * st.f_frsize
    except OSError:
        disk = None
    try:
        uptime = int(float(Path("/proc/uptime").read_text().split()[0]))
    except (OSError, ValueError, IndexError):
        uptime = None
    return MachineStats(temp, disk, uptime)


def format_bytes(n: int) -> tuple[str, str]:
    gb = n / 1e9
    if gb >= 100:
        return f"{gb:,.0f}", "GB"
    if gb >= 1:
        return f"{gb:.1f}", "GB"
    return f"{n / 1e6:.0f}", "MB"


# --------------------------------------------------------------------------
# Snapshot of everything a frame may show
# --------------------------------------------------------------------------


@dataclass
class Observed:
    """What the display has seen across rounds, kept in memory only."""

    seen_locked: bool = False
    height: int | None = None
    height_changed_at: float | None = None

    def note(self, status: NodeStatus, now: float) -> None:
        if status.state is NodeState.LOCKED:
            self.seen_locked = True
        height = status.block_height
        if height is None:
            return
        if self.height is not None and height != self.height:
            # The health answer has no block time: the age is measured from
            # the round in which the display saw the tip move.
            self.height_changed_at = now if height > self.height else None
        self.height = height

    def block_age_secs(self, now: float) -> int | None:
        return None if self.height_changed_at is None else int(now - self.height_changed_at)


@dataclass(frozen=True)
class Snapshot:
    settings: NodeSettings
    status: NodeStatus
    machine: MachineStats
    hostname: str
    api_port: int
    block_age_secs: int | None = None
    lockable: bool = False
    # The node exposes no token-free count of settled paid admissions, so the
    # live service never fills this in and the face stays skipped.
    paid_today: int | None = None

    @property
    def hosted_by(self) -> str | None:
        return self.settings.hosted_by or self.status.hosted_by


def collect_snapshot(cfg: DisplayConfig, observed: Observed) -> Snapshot:
    node_config = resolve_node_config(cfg.node_config)
    settings = read_node_settings(node_config)
    port = cfg.api_port or settings.api_port
    status = probe_node(lambda path: loopback_get(port, path))
    now = time.monotonic()
    observed.note(status, now)
    return Snapshot(
        settings,
        status,
        read_machine_stats(node_config),
        socket.gethostname().split(".")[0],
        port,
        block_age_secs=observed.block_age_secs(now),
        lockable=cfg.remote_unlock or observed.seen_locked,
    )


# --------------------------------------------------------------------------
# Drawing
# --------------------------------------------------------------------------

# Palette from the BitSov logo.
BG_TOP = (30, 19, 16)
BG_BOTTOM = (52, 31, 24)
COPPER = (214, 140, 72)
GOLD = (240, 190, 120)
CREAM = (245, 225, 200)

DESIGN_SIZE = (160, 128)
LOGO_PATH = Path(__file__).resolve().parent / "assets" / "bitsov-logo-96.png"
FONT_DIRS = ["/usr/share/fonts/truetype/dejavu"]


@dataclass(frozen=True)
class Theme:
    text: object
    muted: object
    accent: object
    gold: object
    rule: object
    ok: object
    warn: object
    bad: object
    ink: object


COLOR = Theme(
    text=CREAM,
    muted=(186, 154, 126),
    accent=COPPER,
    gold=GOLD,
    rule=(84, 52, 36),
    ok=(150, 205, 120),
    warn=GOLD,
    bad=(232, 102, 78),
    ink=BG_TOP,
)
MONO = Theme(text=255, muted=255, accent=255, gold=255, rule=255, ok=255, warn=255, bad=255, ink=0)


def use_font_dir(path: str) -> None:
    FONT_DIRS.insert(0, path)
    font.cache_clear()


def dejavu_path(bold: bool = False) -> Path | None:
    name = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
    for folder in FONT_DIRS:
        path = Path(folder) / name
        if path.is_file():
            return path
    return None


@functools.lru_cache(maxsize=128)
def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    path = dejavu_path(bold)
    if path is not None:
        return ImageFont.truetype(str(path), size)
    f = ImageFont.load_default(size)
    if not isinstance(f, ImageFont.FreeTypeFont):
        raise RuntimeError("Pillow was built without FreeType; reinstall Pillow from wheels")
    return f


def cap(f: ImageFont.FreeTypeFont) -> int:
    """Approximate cap height: what a line of digits or capitals occupies."""
    return round(f.size * 0.73)


class Canvas:
    def __init__(self, size: tuple[int, int], mode: str):
        self.mode = "1" if mode == "1" else "RGB"
        self.mono = self.mode == "1"
        self.w, self.h = size
        self.image = Image.new(self.mode, size, 0)
        self.draw = ImageDraw.Draw(self.image)
        self.theme = MONO if self.mono else COLOR
        self.u = min(self.w / DESIGN_SIZE[0], self.h / DESIGN_SIZE[1])
        self.compact = self.h < 100
        self.pad = self.s(6, 2)
        if not self.mono:
            for y in range(self.h):
                t = y / max(1, self.h - 1)
                color = tuple(round(a + (b - a) * t) for a, b in zip(BG_TOP, BG_BOTTOM))
                self.draw.line([(0, y), (self.w, y)], fill=color)

    def s(self, px: float, minimum: int = 1) -> int:
        """A length from the 160x128 design, scaled to this panel."""
        return max(minimum, round(px * self.u))

    def font(self, px: float, bold: bool = False, minimum: int = 8) -> ImageFont.FreeTypeFont:
        return font(self.s(px, minimum), bold)

    def text_w(self, text: str, f: ImageFont.FreeTypeFont) -> float:
        return self.draw.textlength(text, font=f)

    def fit(self, text: str, max_w: float, size: int, minimum: int = 8, bold: bool = False) -> ImageFont.FreeTypeFont:
        while size > minimum and self.text_w(text, font(size, bold)) > max_w:
            size -= 1
        return font(size, bold)

    def ellipsize(self, text: str, f: ImageFont.FreeTypeFont, max_w: float) -> str:
        if self.text_w(text, f) <= max_w:
            return text
        while text and self.text_w(text + "…", f) > max_w:
            text = text[:-1]
        return text.rstrip() + "…"

    def text(self, xy, text, f, fill, anchor="la") -> None:
        self.draw.text(xy, text, font=f, fill=fill, anchor=anchor)

    def bar(self, y: float) -> float:
        """The copper accent bar across the face; returns the y below it."""
        height = self.s(2)
        self.draw.rectangle((self.pad, round(y), self.w - self.pad - 1, round(y) + height - 1), fill=self.theme.accent)
        return round(y) + height


@functools.lru_cache(maxsize=1)
def logo_rgba() -> Image.Image | None:
    try:
        with Image.open(LOGO_PATH) as src:
            img = src.convert("RGB")
    except OSError:
        return None
    # The asset is the app icon on its own dark tile; fade the tile out so the
    # seed sits directly on the face's gradient.
    tile = Image.new("RGB", img.size, img.getpixel((0, 0)))
    img.putalpha(ImageChops.difference(img, tile).convert("L").point(lambda v: min(255, v * 5)))
    return img


@functools.lru_cache(maxsize=16)
def logo_image(size: int, mono: bool) -> Image.Image | None:
    src = logo_rgba()
    if src is None:
        return None
    img = src.resize((size, size), Image.LANCZOS)
    if mono:
        return img.convert("L").point(lambda v: 255 if v >= 110 else 0).convert("1")
    return img


def draw_logo(c: Canvas, x: float, y: float, size: float) -> None:
    size, x, y = max(4, round(size)), round(x), round(y)
    img = logo_image(size, c.mono)
    if img is None:
        c.draw.ellipse(
            (x, y + size * 0.15, x + size, y + size * 0.85), outline=c.theme.accent, width=max(1, size // 12)
        )
    elif c.mono:
        c.image.paste(255, (x, y), img)
    else:
        c.image.paste(img, (x, y), img)


def draw_wordmark(c: Canvas, x: float, baseline: float, f: ImageFont.FreeTypeFont, centered: bool = False) -> None:
    left = x - c.text_w("BitSov", f) / 2 if centered else x
    c.text((left, baseline), "Bit", f, c.theme.text, "ls")
    c.text((left + c.text_w("Bit", f), baseline), "Sov", f, c.theme.accent, "ls")


def draw_header(c: Canvas, title: str) -> float:
    """Small logo mark, title in copper, accent bar; returns the content top."""
    mark = c.s(15, 8)
    draw_logo(c, c.pad - c.s(1, 0), c.pad, mark)
    f = c.font(11, bold=True)
    x = c.pad + mark + c.s(4, 2)
    c.text((x, c.pad + mark / 2), c.ellipsize(title, f, c.w - x - c.pad), f, c.theme.accent, "lm")
    return c.bar(c.pad + mark + c.s(3, 1))


def draw_footer(c: Canvas, text: str, color) -> float:
    """A centred tagline on the bottom edge; returns the y above it. Compact panels skip it."""
    if c.compact:
        return c.h - c.pad
    f = c.font(10)
    c.text((c.w / 2, c.h - c.pad), c.ellipsize(text, f, c.w - 2 * c.pad), f, color, "ms")
    return c.h - c.pad - cap(f) - c.s(5)


Item = tuple[float, Callable[[float], None]]


def stack(c: Canvas, top: float, bottom: float, items: list[Item], gap: float) -> None:
    """Draw items (height, draw(y_top)) centred vertically between top and bottom."""
    total = sum(h for h, _ in items) + gap * (len(items) - 1)
    y = top + max(0.0, (bottom - top - total) / 2)
    for height, draw in items:
        draw(y)
        y += height + gap


def text_item(c: Canvas, text: str, size: float, color, bold: bool = False, minimum: int = 8) -> Item:
    f = c.fit(text, c.w - 2 * c.pad, c.s(size, minimum), minimum, bold)
    text = c.ellipsize(text, f, c.w - 2 * c.pad)
    height = cap(f)
    return height, lambda y: c.text((c.w / 2, y + height), text, f, color, "ms")


def badge_item(c: Canvas, text: str, fill, size: float) -> Item:
    padx, pady = c.s(7, 3), c.s(3, 1)
    f = c.fit(text, c.w - 2 * c.pad - 2 * padx, c.s(size, 8), 7, bold=True)
    width, height = c.text_w(text, f) + 2 * padx, cap(f) + 2 * pady

    def draw(y: float) -> None:
        box = (c.w / 2 - width / 2, y, c.w / 2 + width / 2, y + height)
        c.draw.rounded_rectangle(box, radius=height / 2, fill=fill)
        c.text((c.w / 2, y + pady + cap(f)), text, f, c.theme.ink, "ms")

    return height, draw


def draw_rows(c: Canvas, rows: list[tuple[str, str, str]], top: float, bottom: float) -> None:
    """(label, value, unit) rows: label left, big bold value and unit right."""
    t = c.theme
    row_h = (bottom - top) / max(1, len(rows))
    small = c.font(10)
    for i, (label, value, unit) in enumerate(rows):
        y0 = top + i * row_h
        unit_w = c.text_w(" " + unit, small) if unit else 0
        room = c.w - 2 * c.pad - c.text_w(label, small) - unit_w - c.s(6)
        vf = c.fit(value, room, min(c.s(18), int(row_h * 0.78)), 8, bold=True)
        base = y0 + (row_h + cap(vf)) / 2
        c.text((c.pad, base), label, small, t.muted, "ls")
        right = c.w - c.pad
        if unit:
            c.text((right, base), unit, small, t.gold, "rs")
            right -= unit_w
        c.text((right, base), value, vf, t.text, "rs")
        if i < len(rows) - 1 and not c.mono:
            y = round(y0 + row_h)
            c.draw.line([(c.pad, y), (c.w - c.pad - 1, y)], fill=t.rule)


# --------------------------------------------------------------------------
# The six faces
# --------------------------------------------------------------------------


def state_badge(snap: Snapshot) -> tuple[str, str]:
    st = snap.status
    if st.state is NodeState.LOCKED:
        return "LOCKED", "unlock from your Mac"
    if st.state is NodeState.RUNNING:
        return "RUNNING", f"up {format_uptime(st.uptime_secs)}" if st.uptime_secs is not None else ""
    if st.state is NodeState.SETUP:
        return "NOT SET UP", "finish setup from your Mac"
    return "OFFLINE", f"no answer on 127.0.0.1:{snap.api_port}"


def face_bitsov(c: Canvas, snap: Snapshot) -> None:
    t = c.theme
    label, sub = state_badge(snap)
    color = {
        NodeState.RUNNING: t.ok,
        NodeState.LOCKED: t.warn,
        NodeState.OFFLINE: t.bad,
    }.get(snap.status.state, t.text)

    if c.compact:
        size = c.h - 2 * c.pad
        draw_logo(c, c.pad, c.pad, size)
        x = c.pad + size + c.s(4, 2)
        avail = c.w - x - c.pad
        wf = c.fit("BitSov", avail, c.s(22), 9, bold=True)
        draw_wordmark(c, x, c.pad + cap(wf), wf)
        bf = c.fit(label, avail - 6, 11, 7, bold=True)
        top = c.pad + cap(wf) + 4
        c.draw.rounded_rectangle((x, top, x + avail, top + cap(bf) + 5), radius=3, fill=color)
        c.text((x + avail / 2, top + cap(bf) + 2), label, bf, t.ink, "ms")
        if sub:
            sf = font(8)
            c.text((x, c.h - c.pad), c.ellipsize(sub, sf, avail), sf, t.text, "ls")
        return

    if c.w >= c.h * 1.15:
        size = c.s(58)
        draw_logo(c, c.pad - c.s(2, 0), c.pad, size)
        x = c.pad + size + c.s(4)
        wf = c.fit("BitSov", c.w - x - c.pad, c.s(24), 10, bold=True)
        mid = c.pad + size / 2
        draw_wordmark(c, x, mid, wf)
        c.text((x, mid + c.s(5)), "home node", c.font(11), t.gold, "la")
        top = c.bar(c.pad + size + c.s(5))
    else:
        size = round(min(c.w * 0.5, c.h * 0.36))
        draw_logo(c, (c.w - size) / 2, c.pad, size)
        wf = c.fit("BitSov", c.w - 2 * c.pad, c.s(24), 10, bold=True)
        base = c.pad + size + c.s(4) + cap(wf)
        draw_wordmark(c, c.w / 2, base, wf, centered=True)
        hf = c.font(11)
        c.text((c.w / 2, base + c.s(5) + cap(hf)), "home node", hf, t.gold, "ms")
        top = c.bar(base + c.s(12) + cap(hf))

    items = [badge_item(c, label, color, 13)]
    if sub:
        items.append(text_item(c, sub, 10, t.text))
    stack(c, top, c.h - c.pad, items, c.s(6))


def face_price(c: Canvas, snap: Snapshot) -> None:
    top = draw_header(c, "PRICE PER ACT")
    tagline = "never 0 · rises with fees" if snap.settings.chain_aware else "never 0"
    bottom = draw_footer(c, tagline, c.theme.gold)
    rows = [(label, *sats_parts(msat)) for label, msat in price_rows(snap.settings)]
    draw_rows(c, rows, top + c.s(2), bottom)


def face_paid(c: Canvas, snap: Snapshot) -> None:
    top = draw_header(c, "PAID ACTS TODAY")
    bottom = draw_footer(c, "settled and received", c.theme.muted)
    stack(c, top, bottom, [text_item(c, f"{snap.paid_today:,}", 46, c.theme.text, bold=True)], 0)


def block_age_text(secs: int | None) -> str:
    if secs is None:
        return "watching for the next block"
    if secs < 60:
        return "new block just now"
    hours, minutes = divmod(secs // 60, 60)
    return f"last block {hours} h {minutes} min ago" if hours else f"last block {minutes} min ago"


def face_bitcoin(c: Canvas, snap: Snapshot) -> None:
    t = c.theme
    top = draw_header(c, "BITCOIN")
    items = [
        text_item(c, f"{snap.status.block_height:,}", 34, t.text, bold=True),
        text_item(c, "block height", 11, t.gold),
        text_item(c, block_age_text(snap.block_age_secs), 10, t.text),
    ]
    stack(c, top, c.h - c.pad, items, c.s(6, 3))


def face_lightning(c: Canvas, snap: Snapshot) -> None:
    t = c.theme
    st = snap.status
    top = draw_header(c, "LIGHTNING")
    items = []
    if st.peers is not None:
        caption = "peer online" if st.peers == 1 else "peers online"
        if c.compact:
            items.append(text_item(c, f"{st.peers:,} {caption}", 32, t.text, bold=True))
        else:
            items.append(text_item(c, f"{st.peers:,}", 32, t.text, bold=True))
            items.append(text_item(c, caption, 11, t.gold))
    color = {Lightning.READY: t.ok, Lightning.RECEIVE_ONLY: t.gold}.get(st.lightning, t.bad)
    items.append(text_item(c, st.lightning.value, 11, color, bold=True))
    if snap.lockable:
        items.append(badge_item(c, "HUB-ONLY WHILE LOCKABLE", t.gold, 9))
    stack(c, top, c.h - c.pad, items, c.s(5, 3))


def face_machine(c: Canvas, snap: Snapshot) -> None:
    m = snap.machine
    top = draw_header(c, "MACHINE")
    rows = []
    if m.cpu_temp_c is not None:
        rows.append(("CPU", f"{m.cpu_temp_c:.0f}", "°C"))
    if m.disk_free_bytes is not None:
        rows.append(("Disk free", *format_bytes(m.disk_free_bytes)))
    if m.uptime_secs is not None:
        rows.append(("Uptime", format_uptime(m.uptime_secs), ""))
    bottom = draw_footer(c, snap.hosted_by or snap.hostname, c.theme.gold)
    draw_rows(c, rows, top + c.s(2), bottom)


FACE_RENDERERS: dict[str, Callable[[Canvas, Snapshot], None]] = {
    "bitsov": face_bitsov,
    "price": face_price,
    "paid": face_paid,
    "bitcoin": face_bitcoin,
    "lightning": face_lightning,
    "machine": face_machine,
}


def face_available(name: str, snap: Snapshot) -> bool:
    if name == "price":
        return snap.settings.readable
    if name == "paid":
        return snap.paid_today is not None
    if name == "bitcoin":
        return snap.status.block_height is not None
    if name == "lightning":
        return snap.status.lightning is not None
    if name == "machine":
        return snap.machine.any
    return True


def round_faces(faces: Iterable[str], snap: Snapshot) -> list[str]:
    return [name for name in faces if face_available(name, snap)]


def render_face(name: str, size: tuple[int, int], mode: str, snap: Snapshot) -> Image.Image:
    c = Canvas(size, mode)
    FACE_RENDERERS[name](c, snap)
    return c.image


# --------------------------------------------------------------------------
# Hardware: detection and devices
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PanelSpec:
    driver: str
    width: int
    height: int
    rotate: int = 0
    i2c_address: int | None = None
    fb_device: str | None = None


class Hardware:
    """Read-only discovery. Swapped for a fake in tests."""

    def framebuffers(self) -> list[tuple[str, str]]:
        found = []
        for sysdir in sorted(Path("/sys/class/graphics").glob("fb[0-9]*")):
            try:
                name = (sysdir / "name").read_text().strip()
            except OSError:
                continue
            found.append((f"/dev/{sysdir.name}", name))
        return found

    def i2c_status(self, port: int, address: int) -> int | None:
        if not Path(f"/dev/i2c-{port}").exists():
            return None
        try:
            from smbus2 import SMBus

            with SMBus(port) as bus:
                return bus.read_byte(address)
        except (OSError, ImportError):
            return None

    def spidev(self, port: int, device: int) -> bool:
        return Path(f"/dev/spidev{port}.{device}").exists()


# HDMI/firmware consoles, never the case panel.
_PRIMARY_FB = ("vc4", "bcm2708", "simple", "efifb", "hdmi")


def panel_framebuffer(hw: Hardware) -> str | None:
    for path, name in hw.framebuffers():
        if not any(tag in name.lower() for tag in _PRIMARY_FB):
            return path
    return None


def guess_oled_driver(status: int) -> str:
    """Heuristic: SH1106 status reads tend to have 0x08 in the low nibble;
    SSD1306 does not. Misdetection only shifts the image; override `driver`."""
    return "sh1106" if status & 0x0F == 0x08 else "ssd1306"


def detect_panel(cfg: DisplayConfig, hw: Hardware) -> PanelSpec | None:
    def sized(driver: str, **extra) -> PanelSpec:
        w, h = (cfg.width, cfg.height) if cfg.width else DEFAULT_SIZES[driver]
        return PanelSpec(driver, w, h, cfg.rotate, **extra)

    if cfg.driver == "fbdev" or (cfg.driver == "auto" and cfg.fb_device):
        path = cfg.fb_device or panel_framebuffer(hw)
        return PanelSpec("fbdev", 0, 0, cfg.rotate, fb_device=path) if path else None
    if cfg.driver in I2C_DRIVERS:
        return sized(cfg.driver, i2c_address=cfg.i2c_address or OLED_ADDRESSES[0])
    if cfg.driver in SPI_DRIVERS:
        return sized(cfg.driver)

    path = panel_framebuffer(hw)
    if path:
        return PanelSpec("fbdev", 0, 0, cfg.rotate, fb_device=path)
    for address in (cfg.i2c_address,) if cfg.i2c_address else OLED_ADDRESSES:
        status = hw.i2c_status(cfg.i2c_port, address)
        if status is not None:
            return sized(guess_oled_driver(status), i2c_address=address)
    if hw.spidev(cfg.spi_port, cfg.spi_device):
        log.warning("SPI panels cannot be identified electrically; guessing st7789. Set driver in display.toml.")
        return sized("st7789")
    return None


class FramebufferDevice:
    """Minimal luma-like device for a kernel framebuffer (fbtft / DRM tiny)."""

    FBIOGET_VSCREENINFO = 0x4600

    def __init__(self, path: str, rotate: int = 0):
        import fcntl

        self._fd = os.open(path, os.O_RDWR)
        info = fcntl.ioctl(self._fd, self.FBIOGET_VSCREENINFO, bytes(160))
        xres, yres, _, _, _, _, bpp = struct.unpack_from("7I", info)
        red_offset = struct.unpack_from("I", info, 32)[0]
        if bpp not in (16, 24, 32):
            os.close(self._fd)
            raise OSError(f"{path}: unsupported {bpp} bits per pixel")
        stride_file = Path("/sys/class/graphics") / Path(path).name / "stride"
        self._native = (xres, yres)
        self._bpp = bpp
        self._red_high = red_offset > 0
        self._stride = int(stride_file.read_text()) if stride_file.exists() else xres * bpp // 8
        self.rotate = rotate % 4
        self.size = (yres, xres) if self.rotate % 2 else (xres, yres)
        self.width, self.height = self.size
        self.mode = "RGB"

    def display(self, image: Image.Image) -> None:
        img = image.convert("RGB")
        if self.rotate:
            img = img.rotate(-90 * self.rotate, expand=True)
        data = framebuffer_bytes(img, self._bpp, self._red_high)
        row = self._native[0] * self._bpp // 8
        if row == self._stride:
            os.pwrite(self._fd, data, 0)
        else:
            for y in range(self._native[1]):
                os.pwrite(self._fd, data[y * row : (y + 1) * row], y * self._stride)

    def cleanup(self) -> None:
        try:
            self.display(Image.new("RGB", self.size))
        finally:
            os.close(self._fd)


def framebuffer_bytes(img: Image.Image, bpp: int, red_high: bool = True) -> bytes:
    if bpp == 32:
        return img.tobytes("raw", "BGRX" if red_high else "RGBX")
    if bpp == 24:
        return img.tobytes("raw", "BGR" if red_high else "RGB")
    r, g, b = img.split()
    if not red_high:
        r, b = b, r
    # RGB565 little-endian: lo = GGGBBBBB, hi = RRRRRGGG. Bit fields are disjoint, so add == or.
    lo = ImageChops.add(g.point(lambda v: (v & 0x1C) << 3), b.point(lambda v: v >> 3))
    hi = ImageChops.add(r.point(lambda v: v & 0xF8), g.point(lambda v: v >> 5))
    return Image.merge("LA", (lo, hi)).tobytes()


@contextlib.contextmanager
def without_luma_atexit():
    """luma pins every device it builds in an atexit hook. run() reopens the
    panel every round and closes it itself, so those hooks would only leak."""
    import luma.core.device as luma_device

    real = luma_device.atexit
    luma_device.atexit = types.SimpleNamespace(register=lambda fn, *args, **kwargs: fn)
    try:
        yield
    finally:
        luma_device.atexit = real


def open_device(spec: PanelSpec, cfg: DisplayConfig):
    if spec.driver == "fbdev":
        return FramebufferDevice(spec.fb_device, spec.rotate)
    if spec.driver in I2C_DRIVERS:
        from luma.core.interface.serial import i2c
        from luma.oled import device as oled

        serial = i2c(port=cfg.i2c_port, address=spec.i2c_address)
        with without_luma_atexit():
            return getattr(oled, spec.driver)(serial, width=spec.width, height=spec.height, rotate=spec.rotate)

    from luma.core.interface.serial import spi
    from luma.lcd import device as lcd

    serial = spi(
        port=cfg.spi_port,
        device=cfg.spi_device,
        bus_speed_hz=cfg.spi_speed_hz,
        gpio_DC=cfg.gpio_dc,
        gpio_RST=cfg.gpio_rst,
    )
    width, height, rotate = spec.width, spec.height, spec.rotate
    if spec.driver in ("st7735", "st7789") and height > width:
        # luma's ST77xx init scans landscape; drive a portrait panel as a rotated landscape one.
        width, height, rotate = height, width, (rotate + 1) % 4
    backlight = {}
    if cfg.gpio_backlight is None:
        backlight["backlight"] = lambda _on: None
    else:
        backlight.update(gpio_LIGHT=cfg.gpio_backlight, active_low=cfg.backlight_active_low)
    with without_luma_atexit():
        return getattr(lcd, spec.driver)(serial, width=width, height=height, rotate=rotate, **backlight)


def close_device(device, keep_picture: bool = False) -> None:
    """Release the panel. keep_picture leaves the image and backlight on for a reopen."""
    if keep_picture and hasattr(device, "persist"):
        device.persist = True
    try:
        device.cleanup()
    except Exception:  # noqa: BLE001 - best effort on a failing bus
        pass


# --------------------------------------------------------------------------
# Modes: service loop, preview, probe
# --------------------------------------------------------------------------


def run(cfg: DisplayConfig, hw: Hardware | None = None, *, sleep=time.sleep, rounds: int | None = None) -> None:
    """Show every available face once per round. Before each later round the
    panel is closed and reopened: the reset pulse and init sequence recover a
    controller frozen by a ribbon-cable glitch."""
    hw = hw or Hardware()
    observed = Observed()
    device = spec = None
    last_state: NodeState | None = None
    done = 0
    try:
        while rounds is None or done < rounds:
            if device is None:
                spec = detect_panel(cfg, hw)
                if spec is None:
                    log.warning("no panel found; retrying in 30 s (run with --probe to inspect)")
                    sleep(30)
                    continue
                try:
                    device = open_device(spec, cfg)
                    log.info("driving %s at %dx%d", spec.driver, *device.size)
                except Exception as e:  # noqa: BLE001 - missing bus/driver must not kill the service
                    log.warning("cannot open %s: %s; retrying in 30 s", spec.driver, e)
                    sleep(30)
                    continue
            elif spec.driver != "fbdev":
                close_device(device, keep_picture=True)
                device = None
                try:
                    device = open_device(spec, cfg)
                except Exception as e:  # noqa: BLE001 - a bus glitch must not kill the service
                    log.warning("cannot re-init %s: %s; retrying in 5 s", spec.driver, e)
                    sleep(5)
                    continue

            snap = collect_snapshot(cfg, observed)
            if snap.status.state is not last_state:
                log.info("node state: %s", snap.status.state.value)
                last_state = snap.status.state
            for name in round_faces(cfg.faces, snap):
                try:
                    device.display(render_face(name, device.size, device.mode, snap))
                except Exception as e:  # noqa: BLE001 - a bus glitch reopens the panel
                    log.warning("display update failed: %s; reopening", e)
                    close_device(device)
                    device = None
                    sleep(5)
                    break
                sleep(cfg.interval_secs)
            done += 1
    finally:
        if device is not None:
            close_device(device)


PREVIEW_SIZE = DESIGN_SIZE


def preview_frames(settings: NodeSettings) -> list[tuple[str, str, Snapshot]]:
    """(file label, face, sample snapshot) for every face and node state."""
    machine = MachineStats(cpu_temp_c=48.3, disk_free_bytes=41_200_000_000, uptime_secs=9 * 86_400 + 5 * 3_600)
    running = NodeStatus(
        NodeState.RUNNING,
        uptime_secs=3 * 86_400 + 4 * 3_600 + 720,
        block_height=966_421,
        peers=5,
        lightning=Lightning.READY,
    )

    def snap(status: NodeStatus, **extra) -> Snapshot:
        return Snapshot(settings, status, machine, "bitsov", settings.api_port, **extra)

    live = snap(running, block_age_secs=4 * 60 + 10, lockable=True, paid_today=7)
    return [
        ("bitsov-running", "bitsov", live),
        ("bitsov-locked", "bitsov", snap(NodeStatus(NodeState.LOCKED))),
        ("bitsov-setup", "bitsov", snap(NodeStatus(NodeState.SETUP))),
        ("bitsov-offline", "bitsov", snap(NodeStatus(NodeState.OFFLINE))),
        ("price", "price", live),
        ("paid", "paid", live),
        ("bitcoin", "bitcoin", live),
        ("lightning", "lightning", live),
        ("machine", "machine", live),
    ]


def write_previews(out_dir: Path, settings: NodeSettings) -> list[Path]:
    """Render every face at 160x128 to PNG, plus a 2x overview. No hardware, no network."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.glob("*.png"):
        old.unlink()
    written, frames = [], []
    for i, (label, face, snap) in enumerate(preview_frames(settings), 1):
        img = render_face(face, PREVIEW_SIZE, "RGB", snap)
        path = out_dir / f"{i:02d}-{label}.png"
        img.save(path, optimize=True)
        written.append(path)
        frames.append(img)

    scale, gap, columns = 2, 10, 3
    w, h = PREVIEW_SIZE[0] * scale, PREVIEW_SIZE[1] * scale
    rows = -(-len(frames) // columns)
    sheet = Image.new("RGB", (columns * (w + gap) + gap, rows * (h + gap) + gap), (18, 12, 10))
    for i, img in enumerate(frames):
        x, y = gap + (i % columns) * (w + gap), gap + (i // columns) * (h + gap)
        sheet.paste(img.resize((w, h), Image.NEAREST), (x, y))
    overview = out_dir / "overview.png"
    sheet.save(overview, optimize=True)
    written.append(overview)
    return written


def probe_report(cfg: DisplayConfig, hw: Hardware) -> str:
    """What the panel hardware looks like on this Pi. Prints no node data."""
    lines = []
    try:
        model = Path("/proc/device-tree/model").read_text().strip("\x00\n")
        lines.append(f"model: {model}")
    except OSError:
        lines.append("model: unknown (not a Raspberry Pi?)")
    backlight = "none" if cfg.gpio_backlight is None else (
        f"GPIO{cfg.gpio_backlight} active {'low' if cfg.backlight_active_low else 'high'}"
    )
    lines.append(
        f"config: profile {cfg.profile or '-'}, driver {cfg.driver}, SPI {cfg.spi_speed_hz / 1e6:g} MHz, "
        f"DC GPIO{cfg.gpio_dc}, RST {'-' if cfg.gpio_rst is None else f'GPIO{cfg.gpio_rst}'}, backlight {backlight}"
    )
    fbs = hw.framebuffers()
    lines.append("framebuffers: " + (", ".join(f"{p} ({n})" for p, n in fbs) or "none"))
    for port in sorted({cfg.i2c_port, 1}):
        for address in OLED_ADDRESSES:
            status = hw.i2c_status(port, address)
            seen = "no answer" if status is None else f"ACK, status 0x{status:02X} -> {guess_oled_driver(status)}?"
            lines.append(f"i2c-{port} 0x{address:02X}: {seen}")
    spis = sorted(glob.glob("/dev/spidev*"))
    lines.append("spidev: " + (", ".join(spis) or "none (enable SPI with raspi-config if the panel is SPI)"))
    for boot in ("/boot/firmware/config.txt", "/boot/config.txt"):
        try:
            text = Path(boot).read_text()
        except OSError:
            continue
        relevant = [line.strip() for line in text.splitlines() if re.match(r"\s*(dtoverlay|dtparam=(spi|i2c))", line)]
        lines.append(f"{boot}: " + ("; ".join(relevant) or "no display/bus overlays"))
        break
    spec = detect_panel(cfg, hw)
    if spec is None:
        lines.append("decision: no panel detected")
    else:
        size = "framebuffer size" if spec.driver == "fbdev" else f"{spec.width}x{spec.height}"
        lines.append(f"decision: {spec.driver} {size} rotate={spec.rotate}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BitSov front display for a Raspberry Pi home node.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="display.toml path")
    parser.add_argument("--node-config", help="konsensus.toml path (read-only, allow-listed keys only)")
    parser.add_argument("--preview", type=Path, metavar="DIR", help="render every face at 160x128 to PNG and exit")
    parser.add_argument("--probe", action="store_true", help="report panel hardware and exit")
    parser.add_argument("--check-config", action="store_true", help="validate display.toml and exit (2 if invalid)")
    parser.add_argument("--font-dir", help="directory holding DejaVuSans.ttf and DejaVuSans-Bold.ttf")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    if args.font_dir:
        use_font_dir(args.font_dir)
    if dejavu_path() is None and not args.check_config:
        log.warning("DejaVu fonts not found (apt install fonts-dejavu-core, or --font-dir); using Pillow's font")

    if args.preview:
        settings = read_node_settings(Path(args.node_config)) if args.node_config else None
        if settings is None or not settings.readable:
            settings = NodeSettings(readable=True, hosted_by="Family Pi")
        for path in write_previews(args.preview, settings):
            print(path)
        return 0

    try:
        cfg = load_display_config(args.config)
    except ConfigError as e:
        log.error("%s", e)
        return 2
    if args.check_config:
        return 0
    if args.node_config:
        cfg = DisplayConfig(**{**cfg.__dict__, "node_config": args.node_config})
    if args.probe:
        print(probe_report(cfg, Hardware()))
        return 0

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        run(cfg)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
