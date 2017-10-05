07/21/2011

To ease development and maintenance of the siw kernel module
source code, it has been splitted into two independent directories
softiwarp/ and softiwarp_old/. both directories keep all files
needed to build a siw kernel module. 

softiwarp/
contains the code aligned to the current linux kernel development
tree. it does not contain any legacy code to run with older kernels.
this code is updated frequently, but runs only on newer kernels.
it has been tested for kernels back to kernel version 2.6.36.2.
code documentation (IMPLEMENTATION.txt) will be updated within
the next days.

softiwarp_old/
contains code which compiles and runs on older kernels, but may
soon break on newer kernels. code maintenance is sloppy and
it is recommended to use the newer softiwarp/ code base if 
possible.


06/13/2014

softiwarp_old/ has been removed.


01/20/2015

With kernel version 3.15 the OFA core changed the way it maintains
registered user communication buffers. The new code would result
in inefficient initialization of RDMA data source or sink location for
a software RDMA stack. Therefore, siw abandons using OFA core
user page management (ib_umem_get() etc.) and implememnts its
own simple, but better suited management of pinned user pages.

05/10/2017

The branch 'dev-siw.mem_ext' implements the required set of kernel
verbs API calls to run siw as provider for both NVMeF initiator
and target. The code only compiles on kernels with version >= 4.12.
It also implements MPA version 2 (RFC 6581) with peer-to-peer mode.
