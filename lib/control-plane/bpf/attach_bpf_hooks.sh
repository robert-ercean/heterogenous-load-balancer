#!/bin/bash

# Attach xdp/bpf hook on ingress of enp7s0 (from clients)
sudo ip link set dev enp7s0 xdpgeneric obj xdp_forward.o sec xdp

# Attach tc/bpf hook on ingress of br0 (from backend)
sudo tc qdisc add dev br0 clsact
sudo tc filter add dev br0 ingress bpf da obj tc_return.o sec tc