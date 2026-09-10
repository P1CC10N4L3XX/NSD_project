#!/bin/bash

set -eu

ip link set eth0 up
ip link set eth1 up

ip addr add 10.1.2.2/30 dev eth0
ip addr add 192.168.2.1/24 dev eth1

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

ip route add default via 10.1.2.1