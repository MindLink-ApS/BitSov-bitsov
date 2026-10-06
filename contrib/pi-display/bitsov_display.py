#!/usr/bin/env python3
"""BitSov front display for a Raspberry Pi home node.

Rotates a few screens on the case's small panel: the BitSov mark, node state,
the node's own price per act, and the box label with its LAN IP.

It is deliberately blind to everything that matters for custody. It talks only
to 127.0.0.1, keeps only an allow-list of fields from those answers, and reads
konsensus.toml through a line filter that discards every line outside that
allow-list before anything is parsed. It never touches the seed, mnemonic,
password, pairing links, tickets, tokens or balances. See README.md.
"""

from __future__ import annotations

import argparse
import functools
import glob
import http.client
import ipaddress
import json
import logging
import math
import os
import re
import signal
import socket
import struct
import sys
import time
import tomllib
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
    ("longform_msat", "Mail", 50),
    ("call_msat", "Call", 10_000),
    ("calendar_msat", "Calendar", 25),
    ("file_ref_msat", "File", 100),
    ("web_content_msat", "Web page", 1_000),
    ("collaboration_msat", "Collab", 25),
    ("realtime_signal_msat", "Call signal", 50),
    ("app_ext_msat", "App", 10),
    ("control_msat", "Control", 1),
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

# The only fields kept from loopback API answers.
PROBE_FIELDS = ("state", "uptime_secs", "hosted_by")

SCREENS = ("logo", "status", "prices", "host")
I2C_DRIVERS = ("ssd1306", "sh1106")
SPI_DRIVERS = ("st7789", "ili9341")
DRIVERS = ("auto", *I2C_DRIVERS, *SPI_DRIVERS, "fbdev")
DEFAULT_SIZES = {
    "ssd1306": (128, 64),
    "sh1106": (128, 64),
    "st7789": (240, 240),
    "ili9341": (320, 240),
}
OLED_ADDRESSES = (0x3C, 0x3D)


class ConfigError(ValueError):
    """display.toml is invalid; the service refuses to guess."""


# --------------------------------------------------------------------------
# display.toml
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class DisplayConfig:
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
    interval_secs: float = 8.0
    screens: tuple[str, ...] = SCREENS


def _int(name: str, value: object, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise ConfigError(f"{name} must be an integer in {lo}..{hi}")
    return value


def _pin(name: str, value: object) -> int | None:
    pin = _int(name, value, -1, 27)
    return None if pin == -1 else pin


def parse_display_config(text: str) -> DisplayConfig:
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"display config is not valid TOML: {e}") from None
    known = {f.name for f in DisplayConfig.__dataclass_fields__.values()}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ConfigError(f"unknown display config keys: {', '.join(unknown)}")

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
        out["spi_speed_hz"] = _int("spi_speed_hz", raw["spi_speed_hz"], 500_000, 52_000_000)
    if "gpio_dc" in raw:
        out["gpio_dc"] = _int("gpio_dc", raw["gpio_dc"], 0, 27)
    for name in ("gpio_rst", "gpio_backlight"):
        if name in raw:
            out[name] = _pin(name, raw[name])
    if "backlight_active_low" in raw:
        if not isinstance(raw["backlight_active_low"], bool):
            raise ConfigError("backlight_active_low must be true or false")
        out["backlight_active_low"] = raw["backlight_active_low"]
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
    if "screens" in raw:
        screens = raw["screens"]
        if (
            not isinstance(screens, list)
            or not screens
            or any(s not in SCREENS for s in screens)
            or len(set(screens)) != len(screens)
        ):
            raise ConfigError(f"screens must be a non-empty list drawn from: {', '.join(SCREENS)}")
        out["screens"] = tuple(screens)
    return DisplayConfig(**out)


def load_display_config(path: Path) -> DisplayConfig:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        log.info("no %s; using auto-detection and defaults", path)
        return DisplayConfig()
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


def format_sats(msat: int) -> str:
    sats = Decimal(msat) / 1000
    number = f"{sats:,.3f}".rstrip("0").rstrip(".")
    return f"{number} sat" if sats == 1 else f"{number} sats"


def price_rows(settings: NodeSettings) -> list[tuple[str, str]]:
    return [
        (label, format_sats(floored_price_msat(settings.prices_msat[key], settings.min_admission_cost_msat)))
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


def _uptime(probe: Probe | None) -> int | None:
    if probe is None or probe.status != 200:
        return None
    return _u64(probe.fields.get("uptime_secs"))


def map_state(lock: Probe, livez: Probe | None = None, health: Probe | None = None) -> NodeStatus:
    """Map loopback answers to what the panel shows.

    Locked router: /api/v1/node/lock answers {"state": "locked"}.
    Bootstrap (first run): /livez answers plain "ok", no lock route.
    Live node: no lock route; /livez carries uptime only when operator probes
    are on, otherwise the redacted public /api/v1/health carries it.
    """
    hosted_by = None
    for probe in (lock, livez, health):
        if probe is not None and probe.status == 200 and hosted_by is None:
            hosted_by = valid_hosted_by(probe.fields.get("hosted_by"))
    if lock.status is None and (livez is None or livez.status is None):
        return NodeStatus(NodeState.OFFLINE)
    if lock.status == 200 and lock.fields.get("state") == "locked":
        return NodeStatus(NodeState.LOCKED, hosted_by=hosted_by)
    if livez is not None and livez.status == 200 and livez.plain_ok and lock.status == 404:
        return NodeStatus(NodeState.SETUP)
    uptime = _uptime(livez)
    return NodeStatus(NodeState.RUNNING, _uptime(health) if uptime is None else uptime, hosted_by)


def probe_node(get: Callable[[str], Probe]) -> NodeStatus:
    lock = get("/api/v1/node/lock")
    if lock.status is None or (lock.status == 200 and lock.fields.get("state") == "locked"):
        return map_state(lock)
    livez = get("/livez")
    if _uptime(livez) is not None or livez.plain_ok:
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
# LAN address (local interface table; no packets sent)
# --------------------------------------------------------------------------

_VIRTUAL_IFACES = ("lo", "docker", "br-", "veth", "virbr", "tailscale", "wg", "tun", "tap", "zt")
_TAILSCALE_NET = ipaddress.ip_network("100.64.0.0/10")


def pick_lan_ip(addrs: Iterable[tuple[str, str]]) -> str | None:
    def rank(item: tuple[str, str]) -> tuple[int, int]:
        name, ip = item
        wired = 0 if name.startswith(("eth", "en")) else 1 if name.startswith(("wlan", "wl")) else 2
        return (0 if ipaddress.ip_address(ip).is_private else 1, wired)

    candidates = []
    for name, ip in addrs:
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if name.startswith(_VIRTUAL_IFACES) or addr.is_loopback or addr.is_link_local:
            continue
        if addr in _TAILSCALE_NET or addr.is_unspecified:
            continue
        candidates.append((name, ip))
    return min(candidates, key=rank)[1] if candidates else None


def interface_ipv4s() -> list[tuple[str, str]]:
    if not sys.platform.startswith("linux"):
        return []
    import fcntl

    siocgifaddr = 0x8915
    found = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for _, name in socket.if_nameindex():
            try:
                packed = fcntl.ioctl(s.fileno(), siocgifaddr, struct.pack("256s", name.encode()[:15]))
            except OSError:
                continue
            found.append((name, socket.inet_ntoa(packed[20:24])))
    return found


# --------------------------------------------------------------------------
# Snapshot of everything a frame may show
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Snapshot:
    settings: NodeSettings
    status: NodeStatus
    lan_ip: str | None
    hostname: str
    api_port: int

    @property
    def hosted_by(self) -> str | None:
        return self.settings.hosted_by or self.status.hosted_by


def collect_snapshot(cfg: DisplayConfig) -> Snapshot:
    settings = read_node_settings(resolve_node_config(cfg.node_config))
    port = cfg.api_port or settings.api_port
    status = probe_node(lambda path: loopback_get(port, path))
    try:
        lan_ip = pick_lan_ip(interface_ipv4s())
    except OSError:
        lan_ip = None
    return Snapshot(settings, status, lan_ip, socket.gethostname().split(".")[0], port)


# --------------------------------------------------------------------------
# Drawing
# --------------------------------------------------------------------------

ORANGE = (247, 147, 26)


@dataclass(frozen=True)
class Theme:
    bg: object
    fg: object
    dim: object
    accent: object
    ok: object
    warn: object
    bad: object


MONO = Theme(bg=0, fg=255, dim=255, accent=255, ok=255, warn=255, bad=255)
COLOR = Theme(
    bg=(0, 0, 0),
    fg=(240, 240, 240),
    dim=(140, 148, 158),
    accent=ORANGE,
    ok=(63, 185, 80),
    warn=(255, 176, 0),
    bad=(248, 81, 73),
)


@functools.lru_cache(maxsize=64)
def font(size: int) -> ImageFont.FreeTypeFont:
    f = ImageFont.load_default(size)
    if not isinstance(f, ImageFont.FreeTypeFont):
        raise RuntimeError("Pillow was built without FreeType; reinstall Pillow from wheels")
    return f


class Canvas:
    def __init__(self, size: tuple[int, int], mode: str):
        self.mode = "1" if mode == "1" else "RGB"
        self.image = Image.new(self.mode, size, 0)
        self.draw = ImageDraw.Draw(self.image)
        self.w, self.h = size
        self.theme = MONO if self.mode == "1" else COLOR
        self.small = self.h <= 80 or self.w <= 128
        self.pad = 2 if self.small else max(6, round(min(size) * 0.05))

    def px(self, fraction: float, minimum: int = 8) -> int:
        return max(minimum, round(min(self.w, self.h) * fraction))

    def text_w(self, text: str, f: ImageFont.FreeTypeFont, bold: int = 0) -> float:
        return self.draw.textlength(text, font=f) + 2 * bold

    def fit(self, text: str, max_w: float, size: int, minimum: int = 8, bold: int = 0) -> ImageFont.FreeTypeFont:
        while size > minimum and self.text_w(text, font(size), bold) > max_w:
            size -= 1
        return font(size)

    def ellipsize(self, text: str, f: ImageFont.FreeTypeFont, max_w: float) -> str:
        if self.text_w(text, f) <= max_w:
            return text
        while text and self.text_w(text + "…", f) > max_w:
            text = text[:-1]
        return text.rstrip() + "…"

    def text(self, xy, text, f, fill, anchor="la", bold=0) -> None:
        self.draw.text(xy, text, font=f, fill=fill, anchor=anchor, stroke_width=bold, stroke_fill=fill)

    def wrap(self, text: str, f: ImageFont.FreeTypeFont, max_w: float, max_lines: int) -> list[str]:
        lines, current = [], ""
        for word in text.split():
            trial = f"{current} {word}".strip()
            if self.text_w(trial, f) <= max_w or not current:
                current = trial
            else:
                lines.append(current)
                current = word
        if current:
            lines.append(current)
        if len(lines) > max_lines:
            lines = lines[: max_lines - 1] + [" ".join(lines[max_lines - 1 :])]
        return [self.ellipsize(line, f, max_w) for line in lines]


def _bezier(p0, p1, p2, steps=12):
    return [
        (
            (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t**2 * p2[0],
            (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t**2 * p2[1],
        )
        for t in (i / steps for i in range(steps + 1))
    ]


def draw_mark(c: Canvas, x: float, y: float, size: float) -> None:
    """The BitSov mark: a shield with a knocked-out bitcoin-style B."""
    t = c.theme

    def p(u, v):
        return (x + u * size, y + v * size)

    shield = (
        [p(0.10, 0.06), p(0.90, 0.06), p(0.90, 0.46)]
        + _bezier(p(0.90, 0.46), p(0.90, 0.80), p(0.50, 0.97))[1:]
        + _bezier(p(0.50, 0.97), p(0.10, 0.80), p(0.10, 0.46))[1:]
    )
    c.draw.polygon(shield, fill=t.accent)

    stroke = max(2, round(size * 0.075))
    left, right_top, right_bottom = 0.33, 0.62, 0.67
    top, mid, bottom = 0.25, 0.50, 0.75
    radius = max(1, round(size * 0.12))
    c.draw.rounded_rectangle((*p(left, top), *p(right_top, mid + 0.02)), radius=radius, outline=t.bg, width=stroke)
    c.draw.rounded_rectangle(
        (*p(left, mid - 0.02), *p(right_bottom, bottom)), radius=radius, outline=t.bg, width=stroke
    )
    # Square off the left side so the bowls read as a B rather than two pills.
    c.draw.rectangle((*p(left, top), p(left, bottom)[0] + stroke - 1, p(left, bottom)[1]), fill=t.bg)
    tick = max(1, round(size * 0.05))
    for u in (0.40, 0.51):
        for v0, v1 in ((0.15, top), (bottom, 0.85)):
            x0 = p(u, 0)[0]
            c.draw.rectangle((x0, p(0, v0)[1], x0 + tick - 1, p(0, v1)[1]), fill=t.bg)


def draw_wordmark(c: Canvas, x: float, y: float, size: int, anchor: str = "ls") -> None:
    f = font(size)
    bold = 0 if c.small else max(1, size // 22)
    bit_w = c.text_w("Bit", f, bold)
    total = c.text_w("BitSov", f, bold)
    left = x - total / 2 if anchor[0] == "m" else x
    c.text((left, y), "Bit", f, c.theme.fg, "l" + anchor[1], bold)
    c.text((left + bit_w, y), "Sov", f, c.theme.accent, "l" + anchor[1], bold)


def render_logo(c: Canvas, snap: Snapshot) -> None:
    t = c.theme
    if c.w >= 1.6 * c.h:
        mark = c.h - 2 * c.pad
        draw_mark(c, c.pad, c.pad, mark)
        x = c.pad * 3 + mark
        avail = c.w - x - c.pad
        size = c.h // 3
        while size > 8 and c.text_w("BitSov", font(size)) > avail:
            size -= 1
        draw_wordmark(c, x, c.h / 2 + size * 0.25, size)
        tag = font(max(8, size // 2))
        c.text((x, c.h / 2 + size * 0.25 + tag.size + 2), "home node", tag, t.dim, "ls")
        return
    mark = min(c.w, c.h) * 0.48
    top = c.h * 0.12
    draw_mark(c, (c.w - mark) / 2, top, mark)
    size = c.px(0.16)
    while size > 8 and c.text_w("BitSov", font(size)) > c.w - 2 * c.pad:
        size -= 1
    base = top + mark + c.h * 0.06 + size * 0.75
    draw_wordmark(c, c.w / 2, base, size, "ms")
    c.text((c.w / 2, base + c.px(0.08)), "home node", font(c.px(0.065)), t.dim, "ms")


def _icon(c: Canvas, state: NodeState, cx: float, cy: float, s: float) -> None:
    t = c.theme
    w = max(1, round(s / 9))
    if state is NodeState.LOCKED:
        body = (cx - s * 0.42, cy - s * 0.05, cx + s * 0.42, cy + s * 0.48)
        c.draw.arc((cx - s * 0.28, cy - s * 0.5, cx + s * 0.28, cy + s * 0.06), 180, 360, fill=t.warn, width=w)
        for dx in (-s * 0.28, s * 0.28 - w + 1):
            c.draw.rectangle((cx + dx, cy - s * 0.22, cx + dx + w - 1, cy - s * 0.05), fill=t.warn)
        c.draw.rounded_rectangle(body, radius=max(1, round(s * 0.08)), fill=t.warn)
        k = max(1, s * 0.08)
        c.draw.ellipse((cx - k, cy + s * 0.13 - k, cx + k, cy + s * 0.13 + k), fill=t.bg)
        c.draw.rectangle((cx - k / 2, cy + s * 0.13, cx + k / 2, cy + s * 0.32), fill=t.bg)
        return
    box = (cx - s / 2, cy - s / 2, cx + s / 2, cy + s / 2)
    if state is NodeState.RUNNING:
        c.draw.ellipse(box, fill=t.ok)
        c.draw.line(
            [(cx - s * 0.24, cy + s * 0.02), (cx - s * 0.06, cy + s * 0.2), (cx + s * 0.26, cy - s * 0.18)],
            fill=t.bg,
            width=max(2, w + 1),
            joint="curve",
        )
    elif state is NodeState.OFFLINE:
        c.draw.ellipse(box, outline=t.bad, width=w)
        d = s * 0.5 / math.sqrt(2)
        c.draw.line([(cx - d, cy + d), (cx + d, cy - d)], fill=t.bad, width=w)
    else:
        c.draw.ellipse(box, outline=t.accent, width=w)
        r = max(1, s * 0.06)
        for dx in (-s * 0.22, 0, s * 0.22):
            c.draw.ellipse((cx + dx - r, cy - r, cx + dx + r, cy + r), fill=t.accent)


def status_lines(snap: Snapshot) -> tuple[str, str]:
    st = snap.status
    if st.state is NodeState.LOCKED:
        return "LOCKED", "unlock from your Mac"
    if st.state is NodeState.RUNNING:
        return "Running", f"up {format_uptime(st.uptime_secs)}" if st.uptime_secs is not None else ""
    if st.state is NodeState.SETUP:
        return "Not set up", "finish setup from your Mac"
    return "Node offline", f"no answer on 127.0.0.1:{snap.api_port}"


def render_status(c: Canvas, snap: Snapshot) -> None:
    t = c.theme
    state = snap.status.state
    color = {NodeState.RUNNING: t.ok, NodeState.LOCKED: t.warn, NodeState.OFFLINE: t.bad}.get(state, t.accent)
    title, sub = status_lines(snap)
    header = font(10 if c.small else c.px(0.06))
    c.text((c.pad, c.pad), "BITSOV NODE", header, t.dim)

    if c.small:
        icon = 20
        top = c.pad + header.size + 4
        _icon(c, state, c.pad + icon / 2, top + icon / 2, icon)
        x = c.pad + icon + 6
        big = c.fit(title, c.w - x - c.pad, 16, 10)
        c.text((x, top + icon / 2), title, big, color if c.mode != "1" else t.fg, "lm")
        if sub:
            f = c.fit(sub, c.w - 2 * c.pad, 11, 8)
            c.text((c.pad, c.h - 1), c.ellipsize(sub, f, c.w - 2 * c.pad), f, t.fg, "ls")
        return

    icon = c.px(0.24)
    cy = c.h * 0.36
    _icon(c, state, c.w / 2, cy, icon)
    bold = max(1, c.px(0.004, 1))
    big = c.fit(title, c.w - 2 * c.pad, c.px(0.13), 12, bold)
    base = cy + icon * 0.6 + big.size * 1.05
    c.text((c.w / 2, base), title, big, color, "ms", bold)
    if sub:
        f = c.fit(sub, c.w - 2 * c.pad, c.px(0.07), 9)
        c.text((c.w / 2, base + f.size * 1.6), c.ellipsize(sub, f, c.w - 2 * c.pad), f, t.fg, "ms")


def _price_metrics(size: tuple[int, int]) -> tuple[int, int, int, int]:
    """(title size, row font size, row height, first row top) for a panel size."""
    w, h = size
    if h <= 80 or w <= 128:
        return 11, 10, 10, 14
    m = min(w, h)
    title = max(14, round(m * 0.085))
    row = max(11, round(m * 0.068))
    pad = max(6, round(m * 0.05))
    return title, row, round(row * 1.45), pad + title + round(row * 0.6)


def price_pages(size: tuple[int, int], settings: NodeSettings) -> tuple[int, int]:
    """(page count, rows per page), split evenly so no page holds a lone row."""
    _, row, row_h, top = _price_metrics(size)
    small = size[1] <= 80 or size[0] <= 128
    footer = row + 2 if settings.chain_aware and not small else 0
    fits = max(1, (size[1] - top - footer - (0 if small else 4)) // row_h)
    count = math.ceil(len(PRICE_TABLE) / fits)
    return count, math.ceil(len(PRICE_TABLE) / count)


def render_prices(c: Canvas, snap: Snapshot, index: int, count: int) -> None:
    t = c.theme
    title_size, row_size, row_h, top = _price_metrics((c.w, c.h))
    title = font(title_size)
    c.text((c.pad, c.pad), "Price per act", title, t.accent, "la", 0 if c.small else 1)
    if count > 1:
        c.text((c.w - c.pad, c.pad), f"{index + 1}/{count}", font(max(8, title_size - 2)), t.dim, "ra")
    if not snap.settings.readable:
        f = font(row_size)
        for i, line in enumerate(c.wrap("konsensus.toml not readable", f, c.w - 2 * c.pad, 3)):
            c.text((c.pad, top + i * row_h), line, f, t.fg)
        return
    _, per_page = price_pages((c.w, c.h), snap.settings)
    rows = price_rows(snap.settings)[index * per_page : (index + 1) * per_page]
    f = font(row_size)
    for i, (label, value) in enumerate(rows):
        y = top + i * row_h + row_size
        c.text((c.pad, y), label, f, t.fg, "ls")
        c.text((c.w - c.pad, y), value, f, t.accent if c.mode != "1" else t.fg, "rs")
        if not c.small and i < len(rows) - 1:
            line_y = y + (row_h - row_size) / 2 + 1
            c.draw.line([(c.pad, line_y), (c.w - c.pad, line_y)], fill=(38, 42, 48))
    if snap.settings.chain_aware and not c.small:
        c.text((c.pad, c.h - c.pad), "base price, rises with fees", font(row_size - 2), t.dim, "ls")


def render_host(c: Canvas, snap: Snapshot) -> None:
    t = c.theme
    label = snap.hosted_by
    heading = "Hosted by" if label else "This node"
    name = label or snap.hostname
    ip = snap.lan_ip or "no LAN address"
    avail = c.w - 2 * c.pad
    if c.small:
        c.text((c.pad, c.pad), heading, font(10), t.dim)
        f = c.fit(name, avail, 13, 10)
        lines = c.wrap(name, f, avail, 2 if len(name) > 16 else 1)
        for i, line in enumerate(lines):
            c.text((c.pad, 14 + i * (f.size + 1)), line, f, t.fg)
        c.text((c.pad, c.h - 1), "LAN", font(9), t.dim, "ls")
        ipf = c.fit(ip, avail - 20, 13, 9)
        c.text((c.w - c.pad, c.h - 1), ip, ipf, t.fg, "rs")
        return
    hf = font(c.px(0.065))
    c.text((c.pad, c.pad), heading, hf, t.dim)
    nf = c.fit(name, avail, c.px(0.11), 12)
    lines = c.wrap(name, nf, avail, 2)
    y = c.pad + hf.size * 1.5
    for line in lines:
        c.text((c.pad, y), line, nf, t.accent, "la", max(1, c.px(0.004, 1)))
        y += nf.size * 1.2
    c.text((c.pad, c.h * 0.62), "LAN IP", hf, t.dim)
    ipf = c.fit(ip, avail, c.px(0.12), 12)
    c.text((c.pad, c.h * 0.62 + hf.size * 1.4), ip, ipf, t.fg, "la", max(1, c.px(0.004, 1)))


@dataclass(frozen=True)
class Page:
    screen: str
    index: int = 0
    count: int = 1


def build_pages(screens: Iterable[str], size: tuple[int, int], settings: NodeSettings) -> list[Page]:
    pages = []
    for screen in screens:
        if screen == "prices" and settings.readable:
            count, _ = price_pages(size, settings)
            pages.extend(Page(screen, i, count) for i in range(count))
        else:
            pages.append(Page(screen))
    return pages


def render_page(page: Page, size: tuple[int, int], mode: str, snap: Snapshot) -> Image.Image:
    c = Canvas(size, mode)
    if page.screen == "logo":
        render_logo(c, snap)
    elif page.screen == "status":
        render_status(c, snap)
    elif page.screen == "prices":
        render_prices(c, snap, page.index, page.count)
    elif page.screen == "host":
        render_host(c, snap)
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


def open_device(spec: PanelSpec, cfg: DisplayConfig):
    if spec.driver == "fbdev":
        return FramebufferDevice(spec.fb_device, spec.rotate)
    if spec.driver in I2C_DRIVERS:
        from luma.core.interface.serial import i2c
        from luma.oled import device as oled

        serial = i2c(port=cfg.i2c_port, address=spec.i2c_address)
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
    if spec.driver == "st7789" and height > width:
        # luma's ST7789 init scans landscape; drive a portrait panel as a rotated landscape one.
        width, height, rotate = height, width, (rotate + 1) % 4
    backlight = {}
    if cfg.gpio_backlight is None:
        backlight["backlight"] = lambda _on: None
    else:
        backlight.update(gpio_LIGHT=cfg.gpio_backlight, active_low=cfg.backlight_active_low)
    return getattr(lcd, spec.driver)(serial, width=width, height=height, rotate=rotate, **backlight)


def close_device(device) -> None:
    try:
        device.cleanup()
    except Exception:  # noqa: BLE001 - best effort on a failing bus
        pass
    if hasattr(device, "persist"):
        # luma's atexit hook calls cleanup() again; skip its clear on a closed bus.
        device.persist = True


# --------------------------------------------------------------------------
# Modes: service loop, preview, probe
# --------------------------------------------------------------------------


def run(cfg: DisplayConfig, hw: Hardware | None = None) -> None:
    hw = hw or Hardware()
    device = None
    shown = 0
    last_state: NodeState | None = None
    try:
        while True:
            if device is None:
                spec = detect_panel(cfg, hw)
                if spec is None:
                    log.warning("no panel found; retrying in 30 s (run with --probe to inspect)")
                    time.sleep(30)
                    continue
                try:
                    device = open_device(spec, cfg)
                    log.info("driving %s at %dx%d", spec.driver, *device.size)
                except Exception as e:  # noqa: BLE001 - missing bus/driver must not kill the service
                    log.warning("cannot open %s: %s; retrying in 30 s", spec.driver, e)
                    time.sleep(30)
                    continue

            snap = collect_snapshot(cfg)
            if snap.status.state is not last_state:
                log.info("node state: %s", snap.status.state.value)
                last_state = snap.status.state
            pages = build_pages(cfg.screens, device.size, snap.settings)
            page = pages[shown % len(pages)]
            shown += 1
            try:
                device.display(render_page(page, device.size, device.mode, snap))
            except Exception as e:  # noqa: BLE001 - a bus glitch reopens the panel
                log.warning("display update failed: %s; reopening", e)
                close_device(device)
                device = None
                time.sleep(5)
                continue
            time.sleep(cfg.interval_secs)
    finally:
        if device is not None:
            close_device(device)


PREVIEW_PROFILES = (
    ("oled-128x64", (128, 64), "1"),
    ("st7789-240x240", (240, 240), "RGB"),
    ("st7789-240x320", (240, 320), "RGB"),
    ("ili9341-320x240", (320, 240), "RGB"),
    ("fbdev-480x320", (480, 320), "RGB"),
)


def preview_snapshots(settings: NodeSettings) -> dict[str, Snapshot]:
    def snap(status: NodeStatus) -> Snapshot:
        return Snapshot(settings, status, "192.168.1.42", "bitsov", settings.api_port)

    return {
        "running": snap(NodeStatus(NodeState.RUNNING, uptime_secs=3 * 86_400 + 4 * 3_600 + 720)),
        "locked": snap(NodeStatus(NodeState.LOCKED)),
        "offline": snap(NodeStatus(NodeState.OFFLINE)),
        "setup": snap(NodeStatus(NodeState.SETUP)),
    }


def write_previews(out_dir: Path, settings: NodeSettings) -> list[Path]:
    """Render every screen for every common panel to PNG. No hardware, no network."""
    snaps = preview_snapshots(settings)
    written = []
    tiles = []
    for name, size, mode in PREVIEW_PROFILES:
        scale = max(1, 480 // size[0])
        frames = []
        for page in build_pages(SCREENS, size, settings):
            states = ("running", "locked", "offline", "setup") if page.screen == "status" else ("running",)
            for state in states:
                img = render_page(page, size, mode, snaps[state]).convert("RGB")
                label = page.screen
                if page.screen == "status":
                    label += f"-{state}"
                if page.count > 1:
                    label += f"-{page.index + 1}of{page.count}"
                frames.append((label, img))
        folder = out_dir / name
        folder.mkdir(parents=True, exist_ok=True)
        for old in folder.glob("*.png"):
            old.unlink()
        for i, (label, img) in enumerate(frames, 1):
            path = folder / f"{i:02d}-{label}.png"
            img.resize((size[0] * scale, size[1] * scale), Image.NEAREST).save(path, optimize=True)
            written.append(path)
        tiles.append((name, [img for _, img in frames], scale))

    gap = 12
    rows = [[img.resize((img.width * s, img.height * s), Image.NEAREST) for img in imgs] for _, imgs, s in tiles]
    sheet_w = max(sum(i.width for i in row) + gap * (len(row) + 1) for row in rows)
    sheet_h = sum(max(i.height for i in row) + gap for row in rows) + gap
    sheet = Image.new("RGB", (sheet_w, sheet_h), (60, 60, 64))
    y = gap
    for row in rows:
        x = gap
        for img in row:
            sheet.paste(img, (x, y))
            x += img.width + gap
        y += max(i.height for i in row) + gap
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
    parser.add_argument("--preview", type=Path, metavar="DIR", help="render all screens to PNG and exit")
    parser.add_argument("--probe", action="store_true", help="report panel hardware and exit")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    if args.preview:
        settings = read_node_settings(Path(args.node_config)) if args.node_config else None
        if settings is None or not settings.readable:
            settings = NodeSettings(readable=True, hosted_by="Rasmus's Pi")
        for path in write_previews(args.preview, settings):
            print(path)
        return 0

    try:
        cfg = load_display_config(args.config)
    except ConfigError as e:
        log.error("%s", e)
        return 2
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
