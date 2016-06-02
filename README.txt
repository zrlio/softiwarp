SoftiWARP: Software iWARP kernel driver and user library for Linux.

SoftiWARP (siw) implements the iWARP protocol suite (MPA/DDP/RDMAP,
IETF-RFC 5044/5041/5040) completely in software, without requiring
any dedictaed RDMA hardware. It comprises a loadable Linux kernel
module 'siw' located in kernel/ and a user level library 'libsiw'
located in userlib/.

SoftiWarp targets for integration with the OpenFabrics (OFA)
ecosystem. For OFA integration, it is written against its kernel
and user level interfaces.

SoftiWARP supports both user level and kernel level applications.
It makes use of the OFA connection manager to set up connections.
The kernel component runs on top of TCP kernel sockets.



Prototype
---------

Directory layout:

kernel/:	kernel module
userlib/:	user library
common/:	common include file(s)



Usage:


-> goto userlib dir
	<./autogen.sh>
	<./configure>
	<sudo make install>

-> goto kernel dir
	<make>


	<sudo insmod ./siw.ko>	for binding TX thread to one abritrary CPU
				(check dmesg which CPU runs TX thread)
	or
	<sudo insmod ./siw.ko tx_cpu_list=[n,m,...]
				for starting TX thread on all CPUs given in
				comma separated list, if CPU available

kernel parameters: 	low_delay_tx: default: Y
			setting it to "N" or '0' will put
			tx thread to sleep to be woken up by inbound
			READ.req or SQ resume. Y is 2.5us better than N.

			echo "N" > /sys/module/siw/parameters/low_delay_tx
			to sleep.
