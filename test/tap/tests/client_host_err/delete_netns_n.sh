#!/bin/bash

# NOTE: This script is currently unused, but it's left here because it's useful
# for deleting network namespaces in a easy way. It could be of use for future
# testing.

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

if [ ! "$1" ] || [ ! -z "${1//[0-9]}" ]; then
    echo "Parameter should be a number"
    exit 1
fi

ip netns delete ns$1
ip link delete v-eth$1

