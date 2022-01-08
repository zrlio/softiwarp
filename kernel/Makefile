LINUX_SRC_PATH = /lib/modules/$(shell uname -r)/build

default: modules

install: modules
	@${MAKE} -C $(LINUX_SRC_PATH) M=`pwd` modules_install 
	
modules: 
	@${MAKE} -C $(LINUX_SRC_PATH) M=`pwd` modules 

clean:
	-@${MAKE} -C $(LINUX_SRC_PATH) M=`pwd` clean

.PHONY: clean modules install

