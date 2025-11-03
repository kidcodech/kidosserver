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
PHYSICAL_NIC=${PHYSICAL_NIC:-enp0s31f6}
RUN_DIR="${ROOT_DIR}/data/run"

if [[ $EUID -ne 0 ]]; then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "[kidos] teardown requires root privileges" >&2
    exit 1
  fi
  exec sudo -E PHYSICAL_IF="${PHYSICAL_IF}" DNS_IF="${DNS_IF}" NETNS_NAME="${NS_NAME}" \
    APPS_NS_NAME="${APPS_NS_NAME}" MONITOR_HOST_IF="${MONITOR_HOST_IF}" MONITOR_NS_IF="${MONITOR_NS_IF}" \
    PHYSICAL_NIC="${PHYSICAL_NIC}" "${BASH_SOURCE[0]}"
fi

pkill -f "${ROOT_DIR}/bin/dns-inspector" 2>/dev/null || true
pkill -f "${ROOT_DIR}/bin/monitor" 2>/dev/null || true
pkill -f "${ROOT_DIR}/bin/web" 2>/dev/null || true
pkill -f chromium-browser 2>/dev/null || true
sleep 1
pkill -9 -f "${ROOT_DIR}/bin/monitor" 2>/dev/null || true

rm -f "${RUN_DIR}"/*.pid 2>/dev/null || true

if ip netns list | grep -q "${NS_NAME}"; then
  ip netns exec "${NS_NAME}" ip link set dev "${DNS_IF}" xdp off 2>/dev/null || true
  ip netns exec "${NS_NAME}" tc qdisc del dev "${DNS_IF}" clsact 2>/dev/null || true
else
  tc qdisc del dev "${DNS_IF}" clsact 2>/dev/null || true
fi

if ip netns list | grep -q "${NS_NAME}"; then
  ip netns exec "${NS_NAME}" iptables -t nat -F || true
  ip netns exec "${NS_NAME}" iptables -F || true
  if ip netns exec "${NS_NAME}" ip link show "${PHYSICAL_NIC}" >/dev/null 2>&1; then
    ip netns exec "${NS_NAME}" ip link set "${PHYSICAL_NIC}" down || true
    ip netns exec "${NS_NAME}" ip link set "${PHYSICAL_NIC}" netns 1
    ip link set "${PHYSICAL_NIC}" up || true
    ip addr flush dev "${PHYSICAL_NIC}" || true
  fi
  ip netns delete "${NS_NAME}"
fi

if ip netns list | grep -q "${APPS_NS_NAME}"; then
  ip netns delete "${APPS_NS_NAME}"
fi

if ip link show "${MONITOR_HOST_IF}" >/dev/null 2>&1; then
  ip addr flush dev "${MONITOR_HOST_IF}" 2>/dev/null || true
  ip link set "${MONITOR_HOST_IF}" down 2>/dev/null || true
  ip link delete "${MONITOR_HOST_IF}" 2>/dev/null || true
fi

systemctl start NetworkManager || true

rm -f "${ROOT_DIR}/bpf/include/vmlinux.h"

echo "[kidos] teardown complete"
