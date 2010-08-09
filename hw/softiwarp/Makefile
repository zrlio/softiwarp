#EXTRA_CFLAGS += -DOFA_VERSION=141 -DCHECK_DMA_CAPABILITIES -DTX_FROM_APPL_CPU -DSIW_TX_FULLSEGS
EXTRA_CFLAGS += -DOFA_VERSION=141 -DTX_FROM_APPL_CPU
obj-$(CONFIG_INFINIBAND_SOFTIWARP) += siw.o

siw-y :=  siw_main.o siw_cm.o siw_verbs.o siw_obj.o siw_qp.o siw_qp_tx.o siw_qp_rx.o siw_cq.o siw_cm.o siw_utils.o siw_socket.o siw_ae.o

