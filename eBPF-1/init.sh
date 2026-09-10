#!/bin/bash

set -eu

ip link add bridge0 type bridge vlan_filtering 1

ip link set eth0 master bridge0
ip link set eth1 master bridge0
ip link set eth2 master bridge0

ip link set lo up
ip link set eth0 up
ip link set eth1 up
ip link set eth2 up
ip link set bridge0 up

echo 8 > /sys/class/net/bridge0/bridge/group_fwd_mask

ip addr add 192.168.1.2/24 dev bridge0
ip route add default via 192.168.1.1

ebtables -F
ebtables -P FORWARD DROP
ebtables -P INPUT ACCEPT
ebtables -P OUTPUT ACCEPT

ebtables -A FORWARD -i eth0 -j ACCEPT

if ! pgrep -x hostapd >/dev/null 2>&1; then
    mkdir -p /var/run/hostapd
    hostapd -B /etc/hostapd/hostapd.conf
fi

echo "[eBPF-1] Initialization complete."