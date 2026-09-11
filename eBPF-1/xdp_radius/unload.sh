#!/usr/bin/env bash
# Teardown del sistema di enforcement su eBPF-1: ferma l'enforcer, stacca
# gli XDP, rimuove le mappe pinnate e ripristina la policy ebtables baseline
# (come da init.sh del nodo). Complementare a load_ebpf.sh.
set -uo pipefail

echo "[*] Stopping xdp_user..."
pkill -x xdp_user 2>/dev/null && sleep 1 || true

echo "[*] Detaching XDP..."
for d in eth0 eth1 eth2; do
  ip link set dev "$d" xdp off 2>/dev/null || true
  ip link set dev "$d" xdpgeneric off 2>/dev/null || true
done

echo "[*] Removing pinned maps..."
rm -f /sys/fs/bpf/auth_map /sys/fs/bpf/identity_map 2>/dev/null || true

echo "[*] Resetting ebtables baseline..."
ebtables -F FORWARD 2>/dev/null || true
ebtables -P FORWARD DROP 2>/dev/null || true
ebtables -A FORWARD -i eth0 -j ACCEPT 2>/dev/null || true

echo "[*] unload complete"
