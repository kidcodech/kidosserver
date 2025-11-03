#!/usr/bin/env bash
set -euo pipefail
set -x

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PHYSICAL_IF=${PHYSICAL_IF:-veth0}
DNS_IF=${DNS_IF:-veth1}
NS_NAME=${NETNS_NAME:-testns}
APPS_NS_NAME=${APPS_NS_NAME:-appsns}
MONITOR_HOST_IF=${MONITOR_HOST_IF:-kidos}
MONITOR_NS_IF=${MONITOR_NS_IF:-kidos-peer}
MGMT_HOST_IP=${MGMT_HOST_IP:-192.168.200.1/30}
MGMT_NS_IP=${MGMT_NS_IP:-192.168.200.2/30}
MGMT_HOST_ADDR=${MGMT_HOST_ADDR:-192.168.200.1}
MGMT_NS_ADDR=${MGMT_NS_ADDR:-192.168.200.2}
PHYSICAL_NIC=${PHYSICAL_NIC:-enp0s31f6}
CONFIG_FILE="${ROOT_DIR}/data/config.json"
LOG_DIR="${ROOT_DIR}/data/logs"
RUN_DIR="${ROOT_DIR}/data/run"

if [[ $EUID -ne 0 ]]; then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "[kidos] setup requires root privileges" >&2
    exit 1
  fi
  exec sudo -E PHYSICAL_IF="${PHYSICAL_IF}" DNS_IF="${DNS_IF}" NETNS_NAME="${NS_NAME}" APPS_NS_NAME="${APPS_NS_NAME}" \
    MONITOR_HOST_IF="${MONITOR_HOST_IF}" MONITOR_NS_IF="${MONITOR_NS_IF}" \
    MGMT_HOST_IP="${MGMT_HOST_IP}" MGMT_NS_IP="${MGMT_NS_IP}" \
    MGMT_HOST_ADDR="${MGMT_HOST_ADDR}" MGMT_NS_ADDR="${MGMT_NS_ADDR}" \
    PHYSICAL_NIC="${PHYSICAL_NIC}" "${BASH_SOURCE[0]}"
fi

mkdir -p "${LOG_DIR}" "${RUN_DIR}" "${ROOT_DIR}/bin" "${ROOT_DIR}/data"

if [[ -x "${ROOT_DIR}/scripts/teardown.sh" ]]; then
  PHYSICAL_IF="${PHYSICAL_IF}" DNS_IF="${DNS_IF}" NETNS_NAME="${NS_NAME}" APPS_NS_NAME="${APPS_NS_NAME}" \
    MONITOR_HOST_IF="${MONITOR_HOST_IF}" MONITOR_NS_IF="${MONITOR_NS_IF}" PHYSICAL_NIC="${PHYSICAL_NIC}" \
    "${ROOT_DIR}/scripts/teardown.sh" || true
fi

systemctl stop NetworkManager || true
ip link set "${PHYSICAL_NIC}" down || true

ip netns del "${NS_NAME}" 2>/dev/null || true
ip netns add "${NS_NAME}"
ip netns del "${APPS_NS_NAME}" 2>/dev/null || true
ip netns add "${APPS_NS_NAME}"

ip link delete "${PHYSICAL_IF}" 2>/dev/null || true
ip link add "${PHYSICAL_IF}" type veth peer name "${DNS_IF}"
ip link set "${PHYSICAL_IF}" netns "${APPS_NS_NAME}"
ip link set "${DNS_IF}" netns "${NS_NAME}"

ip link delete "${MONITOR_HOST_IF}" 2>/dev/null || true
ip link add "${MONITOR_HOST_IF}" type veth peer name "${MONITOR_NS_IF}"
ip link set "${MONITOR_NS_IF}" netns "${NS_NAME}"

# Host monitor interface and route
ip addr flush dev "${MONITOR_HOST_IF}" || true
ip addr add "${MGMT_HOST_IP}" dev "${MONITOR_HOST_IF}"
ip link set "${MONITOR_HOST_IF}" up
ip route replace "${MGMT_NS_ADDR}" dev "${MONITOR_HOST_IF}"

# Apps namespace side of kidos
ip netns exec "${NS_NAME}" ip addr flush dev "${MONITOR_NS_IF}" || true
ip netns exec "${NS_NAME}" ip addr add "${MGMT_NS_IP}" dev "${MONITOR_NS_IF}"
ip netns exec "${NS_NAME}" ip link set "${MONITOR_NS_IF}" up

# Apps namespace traffic interface (veth0)
ip netns exec "${APPS_NS_NAME}" ip link set lo up
ip netns exec "${APPS_NS_NAME}" ip addr flush dev "${PHYSICAL_IF}" || true
ip netns exec "${APPS_NS_NAME}" ip addr add 192.168.100.2/24 dev "${PHYSICAL_IF}"
ip netns exec "${APPS_NS_NAME}" ip link set "${PHYSICAL_IF}" up
ip netns exec "${APPS_NS_NAME}" ip route replace default via 192.168.100.1 dev "${PHYSICAL_IF}"

# Network namespace traffic side (veth1) and physical NIC
ip link set "${PHYSICAL_NIC}" netns "${NS_NAME}"
ip netns exec "${NS_NAME}" ip link set lo up
ip netns exec "${NS_NAME}" ip addr flush dev "${DNS_IF}" || true
ip netns exec "${NS_NAME}" ip addr add 192.168.100.1/24 dev "${DNS_IF}"
ip netns exec "${NS_NAME}" ip link set "${DNS_IF}" up

ip netns exec "${NS_NAME}" ip addr flush dev "${PHYSICAL_NIC}" || true
ip netns exec "${NS_NAME}" ip addr add 192.168.8.243/24 dev "${PHYSICAL_NIC}"
ip netns exec "${NS_NAME}" ip link set "${PHYSICAL_NIC}" up
ip netns exec "${NS_NAME}" ip route replace default via 192.168.8.1 dev "${PHYSICAL_NIC}"
ip netns exec "${NS_NAME}" sysctl -w net.ipv4.ip_forward=1
ip netns exec "${NS_NAME}" iptables -t nat -F || true
ip netns exec "${NS_NAME}" iptables -F || true
ip netns exec "${NS_NAME}" iptables -t nat -A POSTROUTING -o "${PHYSICAL_NIC}" -j MASQUERADE
ip netns exec "${NS_NAME}" iptables -A FORWARD -i "${DNS_IF}" -o "${PHYSICAL_NIC}" -j ACCEPT
ip netns exec "${NS_NAME}" iptables -A FORWARD -i "${PHYSICAL_NIC}" -o "${DNS_IF}" -j ACCEPT

systemctl start NetworkManager || true

VETH1_IFINDEX=$(ip netns exec "${NS_NAME}" cat /sys/class/net/${DNS_IF}/ifindex)
MONITOR_IFINDEX=$(ip netns exec "${NS_NAME}" cat /sys/class/net/${MONITOR_NS_IF}/ifindex)
MONITOR_IF_HEX=$(printf "%02x %02x %02x %02x" $((MONITOR_IFINDEX & 0xff)) $(((MONITOR_IFINDEX >> 8) & 0xff)) $(((MONITOR_IFINDEX >> 16) & 0xff)) $(((MONITOR_IFINDEX >> 24) & 0xff)))

WEB_LISTEN="${MGMT_HOST_ADDR}:8080"

python3 - <<PYCONF
import json
path = "${CONFIG_FILE}"
try:
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
except FileNotFoundError:
    cfg = {}

cfg.setdefault("interfaces", {})["physical"] = "${DNS_IF}"
cfg.setdefault("dns", {}).setdefault("blocklist", [])
cfg.setdefault("web", {})["listen"] = "${WEB_LISTEN}"

with open(path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2)
PYCONF

bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${ROOT_DIR}/bpf/include/vmlinux.h"

make -C "${ROOT_DIR}" bpf

cd "${ROOT_DIR}/web/ui"
npm install --legacy-peer-deps
npm run build
rm -rf "${ROOT_DIR}/public/static" 2>/dev/null || true
mkdir -p "${ROOT_DIR}/public"
cp -r dist/* "${ROOT_DIR}/public/"
cd "${ROOT_DIR}"

go build -o "${ROOT_DIR}/bin/dns-inspector" "${ROOT_DIR}/cmd/dns-inspector"
go build -o "${ROOT_DIR}/bin/monitor" "${ROOT_DIR}/cmd/monitor"
go build -o "${ROOT_DIR}/bin/web" "${ROOT_DIR}/cmd/web"

ip netns exec "${NS_NAME}" ip link set dev "${DNS_IF}" xdp off 2>/dev/null || true
ip netns exec "${NS_NAME}" ip link set dev "${DNS_IF}" xdp obj "${ROOT_DIR}/bpf/xdp_dns_redirect.bpf.o" sec xdp

ip netns exec "${NS_NAME}" tc qdisc del dev "${DNS_IF}" clsact 2>/dev/null || true
ip netns exec "${NS_NAME}" tc qdisc add dev "${DNS_IF}" clsact
ip netns exec "${NS_NAME}" tc filter add dev "${DNS_IF}" ingress bpf da obj "${ROOT_DIR}/bpf/tc_mirror.bpf.o" sec tc
ip netns exec "${NS_NAME}" tc filter add dev "${DNS_IF}" egress bpf da obj "${ROOT_DIR}/bpf/tc_mirror.bpf.o" sec tc
ip netns exec "${NS_NAME}" bash -c "set -euo pipefail; \
  IDS=\$(bpftool map show | awk '/name mirror_ifindex/ {gsub(\":\", \"\", \$1); print \$1}'); \
  if [[ -z \"\$IDS\" ]]; then \
    echo '[kidos] failed to locate mirror_ifindex map' >&2; \
    exit 1; \
  fi; \
  for map_id in \$IDS; do \
    bpftool map update id \"\$map_id\" key hex 00 00 00 00 value hex ${MONITOR_IF_HEX}; \
  done"

pkill -f "${ROOT_DIR}/bin/dns-inspector" 2>/dev/null || true
pkill -f "${ROOT_DIR}/bin/monitor" 2>/dev/null || true
pkill -f "${ROOT_DIR}/bin/web" 2>/dev/null || true
sleep 1
pkill -9 -f "${ROOT_DIR}/bin/monitor" 2>/dev/null || true

ip netns exec "${NS_NAME}" env ROOT_DIR="${ROOT_DIR}" LOG_DIR="${LOG_DIR}" RUN_DIR="${RUN_DIR}" \
  bash -c 'nohup "$ROOT_DIR/bin/dns-inspector" >"$LOG_DIR/dns-inspector.log" 2>&1 & echo $! >"$RUN_DIR/dns-inspector.pid"'
nohup "${ROOT_DIR}/bin/monitor" --iface "${MONITOR_HOST_IF}" >"${LOG_DIR}/monitor.log" 2>&1 & echo $! >"$RUN_DIR/monitor.pid"
nohup "${ROOT_DIR}/bin/web" >"${LOG_DIR}/web.log" 2>&1 & echo $! >"$RUN_DIR/web.pid"

case "${WEB_LISTEN}" in
  http://*|https://*) UI_URL="${WEB_LISTEN}" ;;
  :*) UI_URL="http://${MGMT_HOST_ADDR}${WEB_LISTEN}" ;;
  *) UI_URL="http://${WEB_LISTEN}" ;;
esac
echo "[kidos] services started. UI at ${UI_URL}"

CHROMIUM="/usr/bin/chromium-browser"
APP_USER=${SUDO_USER:-$USER}
if [[ -x "${CHROMIUM}" ]]; then
  APP_UID=$(id -u "${APP_USER}" 2>/dev/null || true)
  if [[ -z "${APP_UID}" ]]; then
    echo "[kidos] warning: unable to determine UID for ${APP_USER}; skipping chromium launch" >&2
  else
    CHROM_LOG="/tmp/chrom-${APPS_NS_NAME}.log"
    ip netns exec "${APPS_NS_NAME}" bash -c \
      "nohup sudo -u '${APP_USER}' -E env DISPLAY='${DISPLAY:-}' XDG_RUNTIME_DIR='/run/user/${APP_UID}' WAYLAND_DISPLAY='${WAYLAND_DISPLAY:-}' '${CHROMIUM}' --user-data-dir=/tmp/chrom-${APPS_NS_NAME} >'${CHROM_LOG}' 2>&1 & disown"
    echo "[kidos] chromium launched in ${APPS_NS_NAME}; logs at ${CHROM_LOG}" >&2
  fi
else
  echo "[kidos] warning: chromium-browser not found; skipping launch" >&2
fi
