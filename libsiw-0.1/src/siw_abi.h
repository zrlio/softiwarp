#ifndef _SIW_ABI_H
#define _SIW_ABI_H


#include <infiniband/kern-abi.h>


/*
 * response structures for resource allocation calls
 */

struct siw_alloc_pd {
	struct ibv_alloc_pd ofa_cmd;
};

struct siw_alloc_pd_resp {
	struct ibv_alloc_pd_resp ofa_resp;
	uint32_t pd_id;
};

struct siw_alloc_ucontext_resp {
	struct ibv_get_context_resp ofa_resp;
};

struct siw_cmd_reg_umr_req {
	struct ibv_reg_mr ofa_req;
	uint8_t	 stag_key;
	uint8_t reserved[3];
	uint32_t pbl_addr;
};

struct siw_cmd_reg_umr_resp {
	struct ibv_reg_mr_resp ofa_resp;
	uint32_t stag;
	uint32_t pbl_addr;
};

struct siw_cmd_create_cq {
	struct ibv_create_cq ofa_cmd;
};

struct siw_cmd_create_cq_resp {
	struct ibv_create_cq_resp ofa_resp;
	uint32_t cq_id;
};

struct siw_cmd_create_qp {
	struct ibv_create_qp ofa_cmd;
};

struct siw_cmd_create_qp_resp {
	struct ibv_create_qp_resp ofa_resp;
	uint32_t qp_id;
	uint32_t sq_size;
	uint32_t rq_size;
};

struct siw_cmd_create_srq {
	struct ibv_create_srq ofa_cmd;
};

struct siw_cmd_create_srq_resp {
	struct ibv_create_srq_resp ofa_resp;
};
#endif	/* _SIW_ABI_H */
