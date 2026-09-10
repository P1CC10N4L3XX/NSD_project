#!/usr/bin/env bash
set -euo pipefail

# Carica i due programmi XDP e avvia l'enforcer userspace (xdp_user).
# Topologia deployata del corso (diversa dalla repo di riferimento):
#   bridge0   = bridge con vlan_filtering (init.sh del nodo)
#   eth0      = uplink verso CE2  -> parser RADIUS  (xdp_prog_kern.o)
#   eth1/eth2 = porte client      -> parser EAPOL    (xdp_eap.o)
#   VLAN 10 (client-B1) / 20 (client-B2), RADIUS 192.168.2.10

mkdir -p /sys/fs/bpf /sys/kernel/debug

echo "[*] Mounting bpffs on /sys/fs/bpf..."
umount /sys/fs/bpf 2>/dev/null || true
mount -t bpf bpf /sys/fs/bpf

echo "[*] Mounting debugfs on /sys/kernel/debug..."
mount -t debugfs none /sys/kernel/debug 2>/dev/null || true

echo "[*] bpffs status: $(mount | grep 'on /sys/fs/bpf ' || true)"
echo "[*] fs type: $(stat -f -c %T /sys/fs/bpf)"

echo "[*] Cleaning pinned maps ..."
rm -f /sys/fs/bpf/identity_map /sys/fs/bpf/auth_map 2>/dev/null || true

RADIUS_OBJ="xdp_prog_kern.o"
EAP_OBJ="xdp_eap.o"

if [[ ! -f "$RADIUS_OBJ" ]]; then
  echo "ERROR: $RADIUS_OBJ is missing in the current directory (run make first)"
  exit 1
fi
if [[ ! -f "$EAP_OBJ" ]]; then
  echo "ERROR: $EAP_OBJ is missing in the current directory (run make first)"
  exit 1
fi

RADIUS_PROG="xdp_radius_parse"
EAP_PROG="xdp_eap_parse"

echo "[*] Selected programs:"
echo "    eth0: ${RADIUS_OBJ}:${RADIUS_PROG}"
echo "    eth1/eth2: ${EAP_OBJ}:${EAP_PROG}"

echo "[*] Detaching existing XDP..."
ip link set dev eth0 xdp off 2>/dev/null || true
ip link set dev eth0 xdpgeneric off 2>/dev/null || true
ip link set dev eth1 xdp off 2>/dev/null || true
ip link set dev eth1 xdpgeneric off 2>/dev/null || true
ip link set dev eth2 xdp off 2>/dev/null || true
ip link set dev eth2 xdpgeneric off 2>/dev/null || true

echo "[*] Attaching RADIUS parser on eth0..."
./xdp_loader --dev eth0 --filename "$RADIUS_OBJ" --progname "$RADIUS_PROG"

echo "[*] Attaching EAP parser on eth1..."
./xdp_loader --dev eth1 --filename "$EAP_OBJ" --progname "$EAP_PROG"

echo "[*] Attaching EAP parser on eth2..."
./xdp_loader --dev eth2 --filename "$EAP_OBJ" --progname "$EAP_PROG"

echo "[*] Pinned maps:"
ls -la /sys/fs/bpf | egrep 'identity_map|auth_map' || true

# -------------------------------
# Start userspace program
# -------------------------------

# VLAN 10 -> eth1 (client-B1), VLAN 20 -> eth2 (client-B2)
VLAN_MAP="${VLAN_MAP:-10:eth1,20:eth2}"
BRIDGE="${BRIDGE:-bridge0}"
GATEWAY_IFACE="${GATEWAY_IFACE:-eth0}"
MAP_PATH="${MAP_PATH:-/sys/fs/bpf/auth_map}"
INTERVAL_MS="${INTERVAL_MS:-200}"
LOG_LEVEL="${LOG_LEVEL:-2}"

echo "[*] Userspace config:"
echo "    VLAN_MAP=${VLAN_MAP}"
echo "    BRIDGE=${BRIDGE}"
echo "    GATEWAY_IFACE=${GATEWAY_IFACE}"
echo "    MAP_PATH=${MAP_PATH}"
echo "    INTERVAL_MS=${INTERVAL_MS}"
echo "    LOG_LEVEL=${LOG_LEVEL}"

echo "[*] Starting userspace xdp_user..."
exec ./xdp_user \
  --vlan-map "${VLAN_MAP}" \
  --bridge "${BRIDGE}" \
  --gateway-iface "${GATEWAY_IFACE}" \
  --map-path "${MAP_PATH}" \
  --interval-ms "${INTERVAL_MS}" \
  --log-level "${LOG_LEVEL}"
