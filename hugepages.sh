#!/bin/bash
echo 2048 | sudo tee -a /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
echo 2048 | sudo tee -a /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
