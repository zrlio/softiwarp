LINUX_SRC_PATH = /lib/modules/$(shell uname -r)/build

EXTRA_CFLAGS += -DOFA_VERSION=141 -DCHECK_DMA_CAPABILITIES

obj-m += siw.o

siw-objs :=  siw_main.o siw_cm.o siw_verbs.o siw_obj.o \
	siw_qp.o siw_qp_tx.o siw_qp_rx.o siw_cq.o siw_cm.o \
	siw_debug.o siw_ae.o

default: modules

install: modules
	@${MAKE} -C $(LINUX_SRC_PATH) M=`pwd` modules_install 
	
modules: 
	@${MAKE} -C $(LINUX_SRC_PATH) M=`pwd` modules 

clean:
	-@${MAKE} -C $(LINUX_SRC_PATH) M=`pwd` clean

.PHONY: clean modules install

