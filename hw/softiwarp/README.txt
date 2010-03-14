SoftiWARP: 'siw' Software iWARP kernel driver module.

SoftiWARP (siw) implements the iWARP protocol suite (MPA/DDP/RDMAP,
IETF-RFC 5044/5041/5040) completely in software as a Linux kernel module.
Targeted for integration with OpenFabrics (OFA) interfaces, it appears as
a kernel module in the drivers/infiniband/hw subdirectory of the Linux kernel.
SoftiWARP exports the OFA RDMA verbs interface, currently useable only
for user level applications. It makes use of the OFA connection manager
to set up connections. siw runs on top of TCP kernel sockets.



Status:
=======
siw is work in progress. While the implementation is not complete,
it implements basic connection management, all iWARP wire operations
(SEND, READ, WRITE), and memory protection.



Transmit Path:
==============
If a send queue (SQ) work queue element (wqe) gets posted, siw tries
first to send it directly out of the application context. If the SQ
was non-empty, SQ processing is done by a kernel worker thread.
This thread schedules work, if the tcp socket signals new write
space to be available. If during send operation the socket send space
get exhausted, SQ is abandoned until it resumes via write space available
socket callback.

Packet Fragmentation:
---------------------
siw tries to take into account medium's MTU. FPDU's are constructed not to
exceed the MTU to avoid fragmentation on the wire. Since TCP is a byte stream
protocol, no guarantee can be given if FPDU's are not fragmented.

Zero Copy Send:
---------------
Where allowed by RDMA semantics, siw uses sendpage() for transmitting
user data. This avoids a local data copy operation. As long as the data
are not placed in peers target buffer, any changes to the content of
the local buffer to be sent will result in non predictable target buffer
content. Furthermore, if CRC checksumming is enabled, any change to non
transmitted data already under control of TCP will result in CRC 
corruption. 

Current experimental indicators for using sendpage():

CRC is disabled, AND
operation is a READ.response, OR
operation is a non signalled SEND, OR
operation is a non signalled WRITE.

Furthermore, sendpage() gets used only after a certain threshold of
payload data. All sendpage() usage is experimental and will be extended
to guarantee that the memory must stay resident until the data are
transmitted.


Receive Path:
============-
All application data is directly received within the softirq socket callback
via tcp_read_sock()). This can be easily achieved, since all target
buffers are kernel resident.


Connection Management:
======================
To be rewritten for stability and simplification.  The interaction of
three state machienes (socket, QP, connection endpoint) tends to get
confusing. The iSCSI kernel code gives a good example on how to do TCP
connection management better. Current connection manager code is known
to have bugs and is under change.


Memory Management:
==================
siw currently uses OFA's ib_umem_get() function to pin memory for later
use in data transfer operations. Transmit and receive memory is checked
against correct access permissions only in the moment of access by the
network input path or before pushing it to the socket for transmission.
ib_umem_get() provides DMA mappings for the requested address space which
is not used by siw.


Performance:
============
Overall, performance was not yet our main focus. There is known headroom
for achieving higher performance. 

Fast Path Operations:
While RDMA hardware (RNIC) is typically using a private fast path
between application and RDMA device, siw uses the OFA environment to
post work and to reap work completions through the openfabrics core.
Nevertheless, we do not expect too much overhead from trapping into
the kernel for all post operations, since for a doorbell call the user
library would have to trap into the kernel anyway, and Linux is known for
a very efficient system call implementation anyway.


Debugging:
==========
siw flexibly allows to set different levels of runtime debugging (see
siw_debug.h). Debug level setting is compile-time.


Incomplete List of Missing Functionality:
=========================================
Termination message creation and handling
MPA Reject implementation
Kernel client interface
MPA Marker insertion
MPA Marker reception (not very useful)
Explicit WR fencing


Credits:
========
I wish to thank my collegue Fredy Neeser for substantially
contributing to that implementation. He is the main
author of an early prototype which was not targeted at OFA integration.
Many of his ideas and code have made it into siw.

Philip Frey was helping in siw debugging and early performance
evaluation. Many fruitful discussions improved the quality of the
siw code.


Comments:
=========
Please send comments to Bernard Metzler,
bmt@zurich.ibm.com.
