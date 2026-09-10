#!/bin/bash

set -eu

ip link set eth0 up
ip link set eth1 up
ip link set eth2 up
ip link set lo up


ip addr add 10.100.0.1/30 dev eth0
ip addr add 10.100.0.5/30 dev eth1
ip addr add 10.1.1.1/30 dev eth2


ip addr add 2.255.0.101/32 dev lo


vtysh <<'VTY'
configure terminal
hostname R101
service integrated-vtysh-config

interface lo
    ip address 2.255.0.101/32
interface eth0
    ip address 10.100.0.1/30
interface eth1
    ip address 10.100.0.5/30
interface eth2
    ip address 10.1.1.1/30
router ospf
    ospf router-id 2.255.0.101
    network 2.255.0.101/32 area 0
    network 10.100.0.0/30 area 0
    network 10.100.0.4/30 area 0
    network 10.1.1.0/30 area 0
exit

router bgp 100
    bgp router-id 2.255.0.101
    neighbor 2.255.0.102 remote-as 100
    neighbor 2.255.0.102 update-source 2.255.0.101 
    neighbor 2.255.0.103 remote-as 100
    neighbor 2.255.0.103 update-source 2.255.0.101

    address-family ipv4 unicast
        neighbor 2.255.0.102 next-hop-self
        neighbor 2.255.0.103 next-hop-self
    exit-address-family
exit
end
write memory

VTY

echo "Initialization completed."