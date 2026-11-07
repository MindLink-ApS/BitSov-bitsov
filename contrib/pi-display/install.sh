#!/usr/bin/env bash
# Install the BitSov front display on a Raspberry Pi (Raspberry Pi OS Bookworm or later).
set -euo pipefail

PREFIX=/opt/bitsov-display
CONF_DIR=/etc/bitsov-display
UNIT=/etc/systemd/system/bitsov-display.service
SVC_USER=bitsov-display
GROUPS_NEEDED=(gpio spi i2c video)
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

REPLACED="$CONF_DIR/replaced-services"

usage() {
	cat <<EOF
Usage: sudo ./install.sh [--node-config PATH] [--vendor-service UNIT]... [--enable-buses] [--no-apt] [--no-start]
       sudo ./install.sh --uninstall

  --node-config PATH     the node's konsensus.toml (default: auto-detect a single node)
  --vendor-service UNIT  also stop and disable this display service (repeatable); services
                         holding the panel's SPI device or framebuffer open are found anyway
  --enable-buses         turn on I2C and SPI with raspi-config (needs a reboot)
  --no-apt               skip apt-get (build tools, acl, i2c-tools, DejaVu fonts)
  --no-start             install and enable, but do not (re)start now
EOF
}

die() {
	echo "install.sh: $*" >&2
	exit 1
}

NODE_CONFIG=""
VENDOR_SERVICES=()
APT=1
START=1
ENABLE_BUSES=0
UNINSTALL=0
while [ $# -gt 0 ]; do
	case "$1" in
	--node-config)
		NODE_CONFIG=${2:-}
		shift 2 || die "--node-config needs a path"
		;;
	--vendor-service)
		[[ "${2:-}" =~ ^[A-Za-z0-9@._-]+$ ]] || die "--vendor-service needs a unit name"
		VENDOR_SERVICES+=("${2%.service}.service")
		shift 2
		;;
	--enable-buses) ENABLE_BUSES=1 && shift ;;
	--no-apt) APT=0 && shift ;;
	--no-start) START=0 && shift ;;
	--uninstall) UNINSTALL=1 && shift ;;
	-h | --help) usage && exit 0 ;;
	*) usage >&2 && exit 2 ;;
	esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
[ "$(uname -s)" = Linux ] || die "Linux only; elsewhere use: python3 bitsov_display.py --preview DIR"

configured_node_config() {
	[ -f "$CONF_DIR/display.toml" ] || return 0
	sed -n 's/^node_config *= *"\(.*\)".*/\1/p' "$CONF_DIR/display.toml" | tail -n 1
}

# System services that hold the panel's SPI device or a panel framebuffer open.
panel_holders() {
	local fd target pid unit
	for fd in /proc/[0-9]*/fd/*; do
		target=$(readlink "$fd" 2>/dev/null) || continue
		case "$target" in
		/dev/spidev* | /dev/fb[1-9]*) ;;
		*) continue ;;
		esac
		pid=${fd#/proc/}
		pid=${pid%%/*}
		unit=$(sed -n 's|^0::/system\.slice/\(.*/\)\{0,1\}\([^/]*\.service\)$|\2|p' "/proc/$pid/cgroup" 2>/dev/null)
		[ -n "$unit" ] && [ "$unit" != bitsov-display.service ] && echo "$unit"
	done | sort -u
}

if [ "$UNINSTALL" -eq 1 ]; then
	systemctl disable --now bitsov-display.service 2>/dev/null || true
	rm -f "$UNIT"
	systemctl daemon-reload
	old=$(configured_node_config)
	if [ -n "$old" ] && [ -f "$old" ] && command -v setfacl >/dev/null; then
		setfacl -x "u:$SVC_USER" "$old" || true
	fi
	rm -rf "$PREFIX"
	userdel "$SVC_USER" 2>/dev/null || true
	if [ -f "$REPLACED" ]; then
		while read -r unit; do
			[ -n "$unit" ] && systemctl enable --now "$unit" && echo "Re-enabled $unit."
		done <"$REPLACED"
		rm -f "$REPLACED"
	fi
	echo "Removed the service, $PREFIX and the $SVC_USER user. $CONF_DIR was kept."
	exit 0
fi

python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' ||
	die "Python 3.11+ is required (Raspberry Pi OS Bookworm or later)"

if [ "$APT" -eq 1 ] && command -v apt-get >/dev/null; then
	apt-get update -qq
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
		python3-venv python3-dev build-essential swig acl i2c-tools fonts-dejavu-core
	# Only needed when lgpio has no wheel for this Python; absent on some images.
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq liblgpio-dev 2>/dev/null || true
fi

if [ "$ENABLE_BUSES" -eq 1 ]; then
	command -v raspi-config >/dev/null || die "--enable-buses needs raspi-config"
	raspi-config nonint do_i2c 0
	raspi-config nonint do_spi 0
	echo "I2C and SPI enabled; reboot before the panel can be found."
fi

# --- the node's config: one file, read-only ---------------------------------
if [ -z "$NODE_CONFIG" ]; then
	NODE_CONFIG=$(configured_node_config)
fi
if [ -z "$NODE_CONFIG" ]; then
	found=()
	for f in /home/*/.local/share/konsensus/konsensus.toml /root/.local/share/konsensus/konsensus.toml \
		/var/lib/konsensus/konsensus.toml; do
		[ -f "$f" ] && found+=("$f")
	done
	case ${#found[@]} in
	0) die "no konsensus.toml found; pass --node-config PATH" ;;
	1) NODE_CONFIG=${found[0]} ;;
	*) die "several nodes found (${found[*]}); pass --node-config PATH for the one to show" ;;
	esac
fi
[ -f "$NODE_CONFIG" ] || die "$NODE_CONFIG does not exist"
NODE_CONFIG=$(readlink -f "$NODE_CONFIG")
# The path goes into a systemd unit and a TOML string: keep it to safe characters.
[[ "$NODE_CONFIG" =~ ^/[A-Za-z0-9._/@+-]+$ ]] || die "unsupported characters in $NODE_CONFIG"
[ "$(basename "$NODE_CONFIG")" = konsensus.toml ] || die "$NODE_CONFIG is not a konsensus.toml"

# --- user and groups -------------------------------------------------------
for g in "${GROUPS_NEEDED[@]}"; do
	getent group "$g" >/dev/null || groupadd --system "$g"
done
if ! id "$SVC_USER" >/dev/null 2>&1; then
	useradd --system --user-group --no-create-home --home-dir /nonexistent \
		--shell /usr/sbin/nologin --comment "BitSov front display" "$SVC_USER"
fi
usermod -a -G "$(
	IFS=,
	echo "${GROUPS_NEEDED[*]}"
)" "$SVC_USER"

# Read access to konsensus.toml only. The node's other files keep their modes,
# and the unit maps nothing else from the data directory into the service.
command -v setfacl >/dev/null || die "setfacl not found (apt-get install acl)"
setfacl -m "u:$SVC_USER:r" "$NODE_CONFIG"

# --- code and venv (root-owned; the service user cannot modify them) ---------
install -d -m 0755 "$PREFIX"
install -m 0644 "$HERE/bitsov_display.py" "$HERE/requirements.txt" "$HERE/README.md" \
	"$HERE/display.toml.example" "$PREFIX/"
install -d -m 0755 "$PREFIX/assets"
install -m 0644 "$HERE/assets/bitsov-logo-96.png" "$PREFIX/assets/"
rm -rf "$PREFIX/venv"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --quiet --no-cache-dir --upgrade pip
"$PREFIX/venv/bin/pip" install --quiet --no-cache-dir --require-virtualenv -r "$PREFIX/requirements.txt"

# --- display config ----------------------------------------------------------
install -d -m 0755 "$CONF_DIR"
if [ -f "$CONF_DIR/display.toml" ] &&
	! "$PREFIX/venv/bin/python" "$PREFIX/bitsov_display.py" --config "$CONF_DIR/display.toml" --check-config; then
	old="$CONF_DIR/display.toml.old-$(date +%Y%m%d%H%M%S)"
	mv "$CONF_DIR/display.toml" "$old"
	echo "The existing display.toml is not valid for this version; moved it to $old."
fi
if [ ! -f "$CONF_DIR/display.toml" ]; then
	install -m 0644 "$HERE/display.toml.example" "$CONF_DIR/display.toml"
fi
if grep -q '^node_config *=' "$CONF_DIR/display.toml"; then
	sed -i "s|^node_config *=.*|node_config = \"$NODE_CONFIG\"|" "$CONF_DIR/display.toml"
else
	printf '\nnode_config = "%s"\n' "$NODE_CONFIG" >>"$CONF_DIR/display.toml"
fi
# --remote-unlock is an argv switch the display cannot see; take it from the node's unit.
if ! grep -q '^remote_unlock *=' "$CONF_DIR/display.toml" &&
	grep -qsE '^ExecStart=.*konsensus.*--remote-unlock' /etc/systemd/system/*.service \
		/etc/systemd/user/*.service /home/*/.config/systemd/user/*.service; then
	printf 'remote_unlock = true\n' >>"$CONF_DIR/display.toml"
	echo "The node starts with --remote-unlock: the Lightning face shows the hub-only badge."
fi

# --- systemd -------------------------------------------------------------------
sed "s|@NODE_CONFIG@|$NODE_CONFIG|g" "$HERE/bitsov-display.service" >"$UNIT"
chmod 0644 "$UNIT"
command -v systemd-analyze >/dev/null && systemd-analyze verify "$UNIT" || true
systemctl daemon-reload
systemctl enable bitsov-display.service >/dev/null

# --- replace the vendor display service --------------------------------------
# Two programs driving one panel garble it. Units are recorded so --uninstall
# can hand the panel back.
mapfile -t holders < <(panel_holders)
for unit in "${VENDOR_SERVICES[@]}" "${holders[@]}"; do
	[ -n "$unit" ] || continue
	systemctl disable --now "$unit" >/dev/null 2>&1 || systemctl stop "$unit" || true
	grep -qxF "$unit" "$REPLACED" 2>/dev/null || echo "$unit" >>"$REPLACED"
	echo "Replaced the vendor display service $unit (re-enabled by --uninstall)."
done

echo "--- panel probe ---"
runuser -u "$SVC_USER" -- "$PREFIX/venv/bin/python" "$PREFIX/bitsov_display.py" \
	--config "$CONF_DIR/display.toml" --probe || true
echo "-------------------"

if [ "$START" -eq 1 ]; then
	systemctl restart bitsov-display.service
	echo "Started. Logs: journalctl -u bitsov-display -f"
else
	echo "Installed and enabled. Start with: systemctl start bitsov-display"
fi
echo "Node config (read-only): $NODE_CONFIG"
echo "Display config: $CONF_DIR/display.toml"
