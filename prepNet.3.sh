#!/bin/bash
#bricksDir=~/work/NetBricks
#dpdkBinDir=/usr/local/bin
iface_kernel=enp114s0f1
# Only bring the interface down if it exists in the kernel
iface_vfio="enp114s0f0"
if ip link show "$iface_vfio" >/dev/null 2>&1; then
  sudo ip link set "$iface_vfio" down
else
  echo "Interface $iface_vfio not found; skipping 'ip link set down'" >&2
fi
sudo modprobe vfio_pci
#sudo insmod $bricksDir/3rdparty/dpdk/build/kmod/rte_kni.ko "kthread_mode=multiple carrier=on"
sudo dpdk-devbind.py --bind vfio-pci 72:00.0
dpdk-devbind.py --status
nmcli dev set $iface_kernel managed no
sudo ip addr flush dev $iface_kernel
sudo ip addr add 192.168.222.100/24 dev $iface_kernel
sudo ip link set $iface_kernel up
ip addr show dev $iface_kernel


