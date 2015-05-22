LINUX_SRC_PATH = /lib/modules/$(shell uname -r)/build

#
# If building against OFED, include the OFED headers first.
#
ifneq ($(OFA_DIR),)
EXTRA_CFLAGS += -DOFED_BUILD
FOO := -I$(OFA_DIR)/include $(LINUXINCLUDE)
override LINUXINCLUDE=$(FOO)
endif

obj-m += siw.o

siw-objs :=  siw_main.o siw_cm.o siw_verbs.o siw_obj.o \
	siw_qp.o siw_qp_tx.o siw_qp_rx.o siw_cq.o siw_cm.o \
	siw_debug.o siw_ae.o siw_mem.o

default: modules

install: modules
	@${MAKE} -C $(LINUX_SRC_PATH) M=`pwd` modules_install 
	
modules: 
#
# 	if building against OFED, use the OFED Module.symvers
#
	@if [ -f $(OFA_DIR)/Module.symvers ] ; then \
		cp -f $(OFA_DIR)/Module.symvers ./$(modulesymfile); \
	fi;
	@${MAKE} -C $(LINUX_SRC_PATH) M=`pwd` modules 

clean:
	-@${MAKE} -C $(LINUX_SRC_PATH) M=`pwd` clean

.PHONY: clean modules install

