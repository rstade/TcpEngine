#!/bin/bash
sudo dpdk-devbind.py --bind ixgbe 72:00.0
sudo ip addr add 192.168.222.2/24 dev enp114s0f0
sudo ip link set enp114s0f0 up
ip addr show dev enp114s0f0

sudo dpdk-devbind.py --bind ixgbe 72:00.1
sudo ip addr add 192.168.222.100/24 dev enp114s0f1
sudo ip link set enp114s0f1 up
ip addr show dev enp114s0f1

sudo dpdk-devbind.py --status
