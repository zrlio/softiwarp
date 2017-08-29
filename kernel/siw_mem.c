/*
 * Software iWARP device driver for Linux
 *
 * Authors: Animesh Trivedi <atr@zurich.ibm.com>
 *          Bernard Metzler <bmt@zurich.ibm.com>
 *
 * Copyright (c) 2008-2017, IBM Corporation
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *   Redistribution and use in source and binary forms, with or
 *   without modification, are permitted provided that the following
 *   conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of IBM nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <linux/version.h>
#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <rdma/ib_verbs.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/pid.h>
#include <linux/sched/mm.h>

#include "siw.h"
#include "siw_debug.h"

static void siw_umem_update_stats(struct work_struct *work)
{
	struct siw_umem *umem = container_of(work, struct siw_umem, work);
	struct mm_struct *mm_s = umem->mm_s;

	BUG_ON(!mm_s);

	down_write(&mm_s->mmap_sem);
	mm_s->pinned_vm -= umem->num_pages;
	up_write(&mm_s->mmap_sem);

	mmput(mm_s);

	kfree(umem->page_chunk);
	kfree(umem);
}

static void siw_free_plist(struct siw_page_chunk *chunk, int num_pages)
{
	struct page **p = chunk->p;

	while (num_pages--) {
		put_page(*p);
		p++;
	}
}

void siw_umem_release(struct siw_umem *umem)
{
	struct task_struct *task = get_pid_task(umem->pid, PIDTYPE_PID);
	int i, num_pages = umem->num_pages;

	for (i = 0; num_pages; i++) {
		int to_free = min_t(int, PAGES_PER_CHUNK, num_pages);

		siw_free_plist(&umem->page_chunk[i], to_free);
		kfree(umem->page_chunk[i].p);
		num_pages -= to_free;
	}
	put_pid(umem->pid);
	if (task) {
		struct mm_struct *mm_s = get_task_mm(task);

		put_task_struct(task);
		if (mm_s) {
			if (down_write_trylock(&mm_s->mmap_sem)) {
				mm_s->pinned_vm -= umem->num_pages;
				up_write(&mm_s->mmap_sem);
				mmput(mm_s);
			} else {
				/*
				 * Schedule delayed accounting if
				 * mm semaphore not available
				 */
				INIT_WORK(&umem->work, siw_umem_update_stats);
				umem->mm_s = mm_s;
				schedule_work(&umem->work);

				return;
			}
		}
	}
	kfree(umem->page_chunk);
	kfree(umem);
}

void siw_pbl_free(struct siw_pbl *pbl)
{
	kfree(pbl);
}

/*
 * Get physical address backed by PBL element. Address is referenced
 * by linear byte offset into list of variably sized PB elements.
 * Optionally, provide remaining len within current element, and
 * current PBL index for later resume at same element.
 */
u64 siw_pbl_get_buffer(struct siw_pbl *pbl, u64 off, int *len, int *idx)
{
	int i = idx ? *idx : 0;

	while (i < pbl->num_buf) {
		struct siw_pble *pble = &pbl->pbe[i];

		if (pble->pbl_off + pble->size > off) {
			u64 pble_off = off - pble->pbl_off;

			if (len)
				*len = pble->size - pble_off;
			if (idx)
				*idx = i;

			return pble->addr + pble_off;
		}
		i++;
	}
	if (len)
		*len = 0;
	return 0;
}

struct siw_pbl *siw_pbl_alloc(u32 num_buf)
{
	struct siw_pbl *pbl;
	int buf_size = sizeof(*pbl);

	if (num_buf == 0)
		return ERR_PTR(-EINVAL);

	buf_size += ((num_buf - 1) * sizeof(struct siw_pble));

	pbl = kzalloc(buf_size, GFP_KERNEL);
	if (!pbl)
		return ERR_PTR(-ENOMEM);

	pbl->max_buf = num_buf;

	return pbl;
}

struct siw_umem *siw_umem_get(u64 start, u64 len)
{
	struct siw_umem *umem;
	u64 first_page_va;
	unsigned long mlock_limit;
	int num_pages, num_chunks, i, rv = 0;

	if (!can_do_mlock())
		return ERR_PTR(-EPERM);

	if (!len)
		return ERR_PTR(-EINVAL);

	first_page_va = start & PAGE_MASK;
	num_pages = PAGE_ALIGN(start + len - first_page_va) >> PAGE_SHIFT;
	num_chunks = (num_pages >> CHUNK_SHIFT) + 1;

	umem = kzalloc(sizeof(*umem), GFP_KERNEL);
	if (!umem)
		return ERR_PTR(-ENOMEM);

	umem->pid = get_task_pid(current, PIDTYPE_PID);

	down_write(&current->mm->mmap_sem);

	mlock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;

	if (num_pages + current->mm->pinned_vm > mlock_limit) {
		dprint(DBG_ON|DBG_MM,
			": pages req: %d, limit: %lu, pinned: %lu\n",
			num_pages, mlock_limit, current->mm->pinned_vm);
		rv = -ENOMEM;
		goto out;
	}
	umem->fp_addr = first_page_va;

	umem->page_chunk = kcalloc(num_chunks, sizeof(struct siw_page_chunk),
				   GFP_KERNEL);
	if (!umem->page_chunk) {
		rv = -ENOMEM;
		goto out;
	}
	for (i = 0; num_pages; i++) {
		int got, nents = min_t(int, num_pages, PAGES_PER_CHUNK);

		umem->page_chunk[i].p = kcalloc(nents, sizeof(struct page *),
						GFP_KERNEL);
		if (!umem->page_chunk[i].p) {
			rv = -ENOMEM;
			goto out;
		}
		got = 0;
		while (nents) {
			struct page **plist = &umem->page_chunk[i].p[got];

			rv = get_user_pages(first_page_va, nents, FOLL_WRITE,
					    plist, NULL);
			if (rv < 0)
				goto out;

			umem->num_pages += rv;
			current->mm->pinned_vm += rv;
			first_page_va += rv * PAGE_SIZE;
			nents -= rv;
			got += rv;
		}
		num_pages -= got;
	}
out:
	up_write(&current->mm->mmap_sem);

	if (rv > 0)
		return umem;

	siw_umem_release(umem);

	return ERR_PTR(rv);
}

/*
 * DMA mapping/address translation functions.
 * Used to populate siw private DMA mapping functions of
 * struct dma_map_ops. 
 */
static void *siw_dma_generic_alloc(struct device *dev, size_t size,
				   dma_addr_t *dma_handle, gfp_t gfp,
				   unsigned long attrs)
{
	struct page *page;
	void *kva = NULL;

	page = alloc_pages(gfp, get_order(size));
	if (page)
		kva = page_address(page);
	if (dma_handle)
		*dma_handle = (dma_addr_t)kva;

	return kva;
}

static void siw_dma_generic_free(struct device *dev, size_t size,
				 void *vaddr, dma_addr_t dma_handle,
				 unsigned long attrs)
{
	free_pages((unsigned long) vaddr, get_order(size));
}

static dma_addr_t siw_dma_generic_map_page(struct device *dev,
					   struct page *page,
					   unsigned long offset,
					   size_t size,
					   enum dma_data_direction dir,
					   unsigned long attrs)
{
	u64 kva;

	BUG_ON(!valid_dma_direction(dir));

	kva = (u64)page_address(page);
	if (kva)
		kva += offset;
	return kva;
}

static void siw_dma_generic_unmap_page(struct device *dev,
				       dma_addr_t handle,
				       size_t size,
				       enum dma_data_direction dir,
				       unsigned long attrs)
{
	/* NOP */
}

static int siw_dma_generic_map_sg(struct device *dev, struct scatterlist *sgl,
				  int nents, enum dma_data_direction dir,
				  unsigned long attrs)
{
	struct scatterlist *se;
	int i;

	BUG_ON(!valid_dma_direction(dir));

	for_each_sg(sgl, se, nents, i) {
		/* This is just a validity check */
		if (unlikely(page_address(sg_page(se)) == NULL)) {
			nents = 0;
			break;
		}
		se->dma_address =
			(dma_addr_t)(page_address(sg_page(se)) + se->offset);
		sg_dma_len(se) = se->length;
	}
	return nents;
}

static void siw_dma_generic_unmap_sg(struct device *dev,
				    struct scatterlist *sg,
				    int nents,
				    enum dma_data_direction dir,
				    unsigned long attrs)
{
	/* NOP */
}

static void siw_generic_sync_single_for_cpu(struct device *dev,
					    dma_addr_t dma_handle,
					    size_t size,
					    enum dma_data_direction dir)
{
	/* NOP */
}


static void siw_generic_sync_single_for_device(struct device *dev,
					       dma_addr_t dma_handle,
					       size_t size,
					       enum dma_data_direction dir)
{
	/* NOP */
}

static void siw_generic_sync_sg_for_cpu(struct device *dev,
					struct scatterlist *sg,
					int nents,
					enum dma_data_direction dir)
{
	/* NOP */
}

static void siw_generic_sync_sg_for_device(struct device *dev,
					   struct scatterlist *sg,
					   int nents,
					   enum dma_data_direction dir)
{
	/* NOP */
}

static int siw_dma_generic_mapping_error(struct device *dev,
					 dma_addr_t dma_addr)
{
	return dma_addr == 0;
}

static int siw_dma_generic_supported(struct device *dev, u64 mask)
{
	return 1;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
static int siw_dma_generic_set_mask(struct device *dev, u64 mask)
{
	if (!dev->dma_mask || !dma_supported(dev, mask))
		return -EIO;

	*dev->dma_mask = mask;

	return 0;
}
#endif

const struct dma_map_ops siw_dma_generic_ops = {
	.alloc			= siw_dma_generic_alloc,
	.free			= siw_dma_generic_free,
	.map_page		= siw_dma_generic_map_page,
	.unmap_page		= siw_dma_generic_unmap_page,
	.map_sg			= siw_dma_generic_map_sg,
	.unmap_sg		= siw_dma_generic_unmap_sg,
	.sync_single_for_cpu	= siw_generic_sync_single_for_cpu,
	.sync_single_for_device	= siw_generic_sync_single_for_device,
	.sync_sg_for_cpu	= siw_generic_sync_sg_for_cpu,
	.sync_sg_for_device	= siw_generic_sync_sg_for_device,
	.mapping_error		= siw_dma_generic_mapping_error,
	.dma_supported		= siw_dma_generic_supported,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
	.set_dma_mask		= siw_dma_generic_set_mask,
#endif
	.is_phys		= 1
};
