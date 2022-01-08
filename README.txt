SoftiWARP: Software iWARP kernel driver and user library for Linux.

SoftiWARP (siw) implements the iWARP protocol suite (MPA/DDP/RDMAP,
IETF-RFC 5044/5041/5040/7306) completely in software, without requiring
any dedictaed RDMA hardware. It comprises a loadable Linux kernel
module 'siw' located in kernel/ and a user level library 'libsiw'
located in userlib/.

SoftiWarp targets for integration with the OpenFabrics (OFA)
ecosystem. For OFA integration, it is written against its kernel
and user level interfaces.

SoftiWARP supports both user level and kernel level applications.
It makes use of the OFA connection manager to set up connections.
The kernel component runs on top of TCP kernel sockets.
