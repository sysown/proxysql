#!/bin/bash

# NOTE: This script is currently unused, but it's left here because it's useful
# for creating network namespaces in a easy way. It could be of use for future
# testing.

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

if [ ! "$1" ] || [ ! -z "${1//[0-9]}" ]; then
    echo "Parameter should be a number"
    exit 1
fi

ip netns add ns$1

ip netns exec ns$1 ip link set lo up
ip netns exec ns$1 ip link set dev lo up

ip link add v-eth$1 type veth peer name v-peer1
ip link set v-peer1 netns ns$1
ip netns exec ns$1 ip addr
ip netns exec ns$1 ip addr add 10.200.$1.2/24 dev v-peer1
ip netns exec ns$1 ip link set v-peer1 up
ip addr add 10.200.$1.1/24 dev v-eth$1
ip link set v-eth$1 up
ip netns exec ns$1 ip route add default via 10.200.$1.1

