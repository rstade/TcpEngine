## TcpEngine Overview

TcpEngine is the successor of [TrafficEngine](https://github.com/rstade/TrafficEngine) and [ProxyEngine](https://github.com/silverengine-de/proxyengine). It combines the functionality ob both engines into a single codebase. TcpEngine can either run as stateful user-space TCP traffic generator or as a pass-through TCP proxy, optionally with delayed binding. 


## TcpEngine as TCP Traffic Generator

TcpEngine contains a stateful user-space TCP traffic generator written in Rust with following properties
* high performance: some hundred thousand TCP connections per second (cps) per core. 
* supports client and server TCP roles concurrently
* multi-core, shared nothing, locking-free architecture 
* receive flow steering (RFS) by NIC

It may be used for (load-)testing  TCP based application servers and TCP proxies. TcpEngine maintains TCP-state and can therefore setup and release complete TCP connections.

Multi-core scaling is supported by steering packets of the same TCP connection based on the TCP port or the IP address to the appropriate core which handles that connection.  Therefore port resources can be assigned to cores (based on paramater _dst_port_mask_ in the configuration file). Alternatively, if the NIC does not support port masks, steering can be based on the IP address.   

TcpEngine builds on [Netbricks](https://github.com/NetSys/NetBricks) which itself utilizes DPDK for user-space networking. 

**_Testing_**

The executables must currently be run with supervisor rights, as otherwise the DPDK cannot be initialized. However to avoid that Cargo itself must be run under root, the shell script [test.sh](https://github.com/rstade/TcpEngine/blob/master/test.sh) can be used, for example 

* "./test.sh test_as_client  --release"  or  "./test.sh test_as_server  --release". 

The script requires installation of the _jq_ tool, e.g.  by running "yum install jq". 

In addition the script allows to run a simple loopback helper tool, called macswap:
* "./test.sh macswap --release"

This tool can be used in cases the loopback mode of the NIC is not working. This happened with X710DA2. The tool should be run ideally on a second server. It swaps source and destination MAC addresses and sends the frames back towards the origin. 


**_Performance_**

see [TrafficEngine](https://github.com/rstade/TrafficEngine) and [ProxyEngine](https://github.com/silverengine-de/proxyengine).


**_Limitations_**

Currently only a basic TCP state machine without retransmission, flow control, etc., is implemented.


## TcpEngine as (reverse) TCP-Proxy

TcpEngine can run as a user-space TCP-proxy with following properties
* TCP pass-through
* customizable delayed binding
* high performance: more than **1 million TCP connections opened and closed per second using 3 cores**
* multi-core, shared nothing, locking-free architecture
* client side receive side scaling (RSS), server side receive flow steering (RFS) by NIC
* customizable payload inspection and manipulation

It may be used for intelligent load-balancing and fire-walling of TCP based protocols, e.g. LDAP. Late binding allows to select the target server not till the first payload packet after the initial three-way hand-shake is received. In addition, callbacks can be defined by which the proxy can modify the payload of the TCP based protocol. For this purpose additional connection state is maintained by the TcpEngine.

Scaling happens by distributing incoming client-side TCP connections using RSS over the cores and by steering the incoming server side TCP connections to the appropriate core. This receive flow steering can be either based on the port or on the IP address of the server side connection (selected by parameter _flow_steering_ in the toml configuration file). In the first case port resources of the proxy are assigned to cores (based on paramater _dst_port_mask_ in the configuration file). In the second case each core uses a unique IP address for the server side connections.


### Test Configuration of TcpEngine as Proxy 

![tcpengine test configuration](https://github.com/rstade/tcpengine/blob/master/proxyengine_config.png)



## Architecture and Implementation

A high-level overview of TcpEngine is shown in [TcpEngine Architecture](https://github.com/rstade/TcpEngine/blob/main/high-level-architecture.md).

TcpEngine builds on a fork of [Netbricks](https://github.com/NetSys/NetBricks) for the user-space networking.
NetBricks itself utilizes _DPDK_ for fast I/O.
NetBricks uses a significantly higher abstraction level than _DPDK_.
This allows for quick and straight forward implementation of complex network functions by placing building blocks like packet filters and generators, flow splitters and mergers into a directed graph.
As all functions in the graph operate in the same memory space there is no need to copy memory (zero copy approach), or even worse to move packets between VNFs.
This optimizes overall energy consumption and performance.
This is in obvious contrast to classical network function virtualization (NFV) concept using e.g. virtual machines to implement network functions (VNFs).
A very similar zero copy approach is currently followed by the Intel [NFF-Go](https://github.com/intel-go/nff-go) project.

We are using the above concept of NetBricks to implement TcpEngine.
Due to the high abstraction level the network functions itself (nfproxy.rs and nftraffic.rs) encompasses each roughly only about 1000 LOC.
This number includes already a significant amount of code for profiling, recording of TCP sessions, debugging and tracing.

Some specific features of TcpEngine are:
* using Flow Director capabilities in Intel NICs to implement RSS and RFS (tested with 82599 and X710 NICs)
* zero-copy recording of session records including time-stamps for TCP state changes
* timer wheels for scheduling and processing of timer events (e.g. for TCP timeouts)
* load and priority dependent scheduling of flow processing (e.g. for flow merging)
* code profiling feature for performance tuning
* secure multi-threading code based on Rust's borrow checker for memory isolation
* easy integration of C libraries with support by automatic binding [rust-bindgen](https://github.com/rust-lang/rust-bindgen)


## TcpEngine Installation

First install NetBricks. TcpEngine needs the branch e2d2-rstade from the fork at https://github.com/rstade/Netbricks.
The required NetBricks version is tagged.
Install NetBricks locally on your machine by following the description of NetBricks.
The installation path of e2d2 needs to be updated in the dependency section of Cargo.toml of TcpEngine.

Note, that a local installation of NetBricks is necessary as it includes DPDK and some C-libraries for interfacing the Rust code of NetBricks with the DPDK. If the optional KNI interface is needed, the DPDK kernel module needs to be re-compiled each time the kernel version changes. This can be done with the script [build.sh](https://github.com/rstade/NetBricks/blob/e2d2-rstade/build.sh) of NetBricks. Note also that the Linux linker _ld_ needs to be made aware of the location of the .so libraries created by NetBricks. This can be solved using _ldconfig_.

TcpEngine includes a main program bin.rs (using example configurations _\*.toml_) and test modules (using configurations _tests/\*.toml_). For both the network interfaces of the test machine need to be prepared (see [prepNet.sh](https://github.com/rstade/tcpengine/blob/master/prepNet.sh)).

First a network interface for user-space DPDK is needed. This interface is used by the engine to connect to servers (in the example configuration this interface uses PCI slot 07:00.0). The code is tested with NIC X520-DA2 (82599).

Secondly an extra Linux interface is required which is used by the test modules for placing server stacks.

For some integration tests both interfaces must be interconnected. In case of physical interfaces, interfaces may be 
either connected by a cross-over cable or by a switch. In case of virtual interfaces, e.g. interfaces may be connected 
to a host-only network of the hypervisor. Using Wireshark on the linux interface allows us to observe the traffic exchange between clients, the TcpEngine and the servers. However, as wireshark may not keep up with the transmission speeds of modern line cards, packets may be lost.

In addition, some parameters like the Linux interface name (linux_if) and the IP / MAC addresses in the test module configuration files  tests/*.toml need to be adapted.

For performing the tests, follow these steps:

* prepare the environment:  
   - set up hugepages, e.g. using ./hugepages.sh
   - set up DPDK drivers, e.g. using ./prepNet.sh
   - check the network environment, especially IP addresses and IP routing, see for an example: network.test.cfg. 
     Note that often a misconfigured network environment results in failing tests
* use ./test.sh with one of the parameters:
  * test_rf_ip: receive flow steering based on IP address for DelayedProxy or SimpleProxy, config file is
    ./tests/test_rfs_ip.toml
  * test_rfs_port: receive flow steering based on port for DelayedProxy or SimpleProxy, config file is ./tests/test_rfs_port.toml
  * client_syn_fin: special test for receiving pre-mature FIN for DelayedProxy or SimpleProxy
  * test_as_client: test for mode=TrafficGenerator when TcpEngine is the client side of the TCP transactions and 
    server side is a TCP Linux stack
  * test_as_server: test for mode=TrafficGenerator when TcpEngine is the server side ot the TCP transactions and 
    client side is a TCP Linux stack



Below test results are achieved on a 2-socket NUMA server, each socket hosting 4 physical cores, running the real-time kernel of Centos 7.5.






