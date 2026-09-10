set -eu

ip link set eth0 up
ip link set eth1 up

ip addr add 10.1.3.2/30 dev eth0
ip addr add 192.168.1.1/24 dev eth1

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

ip route add default via 10.1.3.1


ip link show eth1.10 > /dev/null 2>&1 || ip link add link eth1 name eth1.10 type vlan id 10
ip link set eth1.20 >/dev/null 2>&1 || ip link add link eth1 name eth1.20 type vlan id 20

ip link set eth1.10 up
ip link set eth1.20 up

ip addr add 192.168.30.1/30 dev eth1.10
ip addr add 192.168.40.1/30 dev eth1.20