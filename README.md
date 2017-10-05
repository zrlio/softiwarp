#SoftiWARP

SoftiWARP (siw) is a software iWARP kernel driver and user library 
for Linux. It implements the iWARP protocol suite (MPA/DDP/RDMAP,
IETF-RFC 5044/5041/5040) completely in software, without requiring
any dedicated RDMA hardware. It comprises a loadable Linux kernel
module `siw` located in `kernel/` and a user level library `libsiw`
located in `userlib/`.


SoftiWarp targets for integration with the OpenFabrics (OFA)
ecosystem. For OFA integration, it is written against its kernel
and user level interfaces.

SoftiWARP supports both user level and kernel level applications.
It makes use of the OFA connection manager to set up connections.
The kernel component runs on top of TCP kernel sockets.

## Code structure
```bash 
kernel/:	kernel module
userlib/:	user library
common/:	common include file(s)
```

## Build and install 

### Linux kernel versions

SoftiWARP code tries to stay up to date with recent Linux kernels.
Git `master` is supposed to run on the newest stable kernel.
To ease code maintenance and to allow for back porting
of any new features, old versions of SoftiWARP will be branched
off with discriptive names. `master` is always tagged with the kernel
version it matches. 

Re-installing a newer SoftiWARP version after a kernel upgrade shall include
making and re-installing both user library and kernel module
(see below).

### User-space library
 
```bash
 cd /path/to/your/clone/userlib
 ./autogen.sh
 ./configure
 make install
```
 
### Kernel module
 To build:
```bash 
cd /path/to/your/clone/kernel
make
```

To load:

settings 1: for starting TX threads on available CPUs 
(check dmesg which CPUs runs TX thread) 
```bash
sudo insmod ./siw.ko
```

setting 2: for starting TX thread on all CPUs given in 
comma separated list, if CPU available. Consider this
option, if you want to run siw on a certain network
device and want to restrict TX threads to the NUMA
node this device is located at
```bash
sudo insmod ./siw.ko tx_cpu_list=[n,m,...]
```

## Contributions

PRs are always welcome. Please fork, and make necessary modifications 
you propose, and let us know. 

## Contact 

If you have questions or suggestions, feel free to post at:

https://groups.google.com/forum/#!forum/zrlio-users

or email: zrlio-users@googlegroups.com

