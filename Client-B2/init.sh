ip addr add 192.168.40.10/24 dev eth0
ip link set eth0 up
ip route add default via 192.168.40.1