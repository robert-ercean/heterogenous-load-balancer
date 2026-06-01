#!/bin/bash

sudo ethtool -L enp39s0 combined 2
sudo ethtool -L enp40s0 combined 2
history | grep mtu
sudo ip link set dev enp39s0 mtu 1500
sudo ip link set dev enp40s0 mtu 1500
