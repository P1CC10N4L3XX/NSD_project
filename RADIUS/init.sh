#!/bin/bash

set -eu

ip link set eth0 up

ip addr add 192.168.2.10/24 dev eth0 2>/dev/null 2>&1 || true
ip route add default via 192.168.2.1 2>/dev/null 2>&1 || true

RDIR="/etc/freeradius/3.0"

mkdir -p $RDIR/mods-config/files

if [ -f /root/freeradius/clients.conf ]; then
    cp /root/freeradius/clients.conf $RDIR/clients.conf
    cp /root/freeradius/users.conf $RDIR/mods-config/files/authorize
else
    echo "clients.conf or users.conf not found in /root/freeradius"
    exit 1
fi

if [ -f /root/freeradius/users.conf ]; then
    cp /root/freeradius/users.conf $RDIR/users.conf
else
    echo "users.conf not found in /root/freeradius"
    exit 1
fi

pkill -x freeradius >/dev/null 2>&1 || true
pkill -x radiusd >/dev/null 2>&1 || true



if command -v freeradius >/dev/null 2>&1; then
    (freeradius -f -l /root/radius.log >/dev/null 2>&1 &)
else
    (radiusd -f -l /root/radius.log >/dev/null 2>&1 &)
fi

sleep 1

echo "RADIUS listening on UDP port 1812:"
ss -lunp | grep ':1812' || echo "RADIUS is not listening on UDP port 1812"

echo "Last FreeRadius log entries:"
tail -n 30 "/root/radius.log" 2>/dev/null || true