/*
 * Software iWARP device driver for Linux
 *
 * Authors: Animesh Trivedi <atr@zurich.ibm.com>
 *          Bernard Metzler <bmt@zurich.ibm.com>
 *
 * Copyright (c) 2008-2011, IBM Corporation
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
#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <rdma/ib_verbs.h>
#include <linux/dma-mapping.h>

#include "siw.h"
#include "siw_verbs.h"

/*
 * DMA mapping/address translation functions.
 * Used to populate siw private DMA mapping functions of
 * struct ib_dma_mapping_ops in struct ib_dev - see rdma/ib_verbs.h
 */

static int siw_mapping_error(struct ib_device *dev, u64 dma_addr)
{
	return dma_addr == 0;
}

static u64 siw_dma_map_single(struct ib_device *dev, void *kva, size_t size,
			       enum dma_data_direction dir)
{
	/* siw uses kernel virtual addresses for data transfer */
	return (u64) kva;
}

static void siw_dma_unmap_single(struct ib_device *dev,
				 u64 addr, size_t size,
				 enum dma_data_direction dir)
{
	/* NOP */
}

static u64 siw_dma_map_page(struct ib_device *dev, struct page *page,
			    unsigned long offset, size_t size,
			    enum dma_data_direction dir)
{
	u64 kva = 0;

	BUG_ON(!valid_dma_direction(dir));

	if (offset + size <= PAGE_SIZE) {
		kva = (u64) page_address(page);
		if (kva)
			kva += offset;
	}
	return kva;
}

static void siw_dma_unmap_page(struct ib_device *dev,
			       u64 addr, size_t size,
			       enum dma_data_direction dir)
{
	/* NOP */
}

static int siw_dma_map_sg(struct ib_device *dev, struct scatterlist *sgl,
			  int n_sge, enum dma_data_direction dir)
{
	struct scatterlist *sg;
	int i;

	BUG_ON(!valid_dma_direction(dir));

	/* This is just a validity check */
	for_each_sg(sgl, sg, n_sge, i)
		if (page_address(sg_page(sg)) == NULL)
			return 0;

	return n_sge;
}

static void siw_dma_unmap_sg(struct ib_device *dev, struct scatterlist *sgl,
			     int n_sge, enum dma_data_direction dir)
{
	/* NOP */
}

static u64 siw_dma_address(struct ib_device *dev, struct scatterlist *sg)
{
	u64 kva = (u64) page_address(sg_page(sg));

	if (kva)
		kva += sg->offset;

	return kva;
}

static unsigned int siw_dma_len(struct ib_device *dev,
				   struct scatterlist *sg)
{
	return sg_dma_len(sg);
}

static void siw_sync_single_for_cpu(struct ib_device *dev, u64 addr,
				    size_t size, enum dma_data_direction dir)
{
	/* NOP */
}

static void siw_sync_single_for_device(struct ib_device *dev, u64 addr,
				       size_t size,
				       enum dma_data_direction dir)
{
	/* NOP */
}

static void *siw_dma_alloc_coherent(struct ib_device *dev, size_t size,
				    u64 *dma_addr, gfp_t flag)
{
	struct page *page;
	void *kva = NULL;

	page = alloc_pages(flag, get_order(size));
	if (page)
		kva = page_address(page);
	if (dma_addr)
		*dma_addr = (u64)kva;

	return kva;
}

static void siw_dma_free_coherent(struct ib_device *dev, size_t size,
				  void *kva, u64 dma_addr)
{
	free_pages((unsigned long) kva, get_order(size));
}

struct ib_dma_mapping_ops siw_dma_mapping_ops = {
	.mapping_error		= siw_mapping_error,
	.map_single		= siw_dma_map_single,
	.unmap_single		= siw_dma_unmap_single,
	.map_page		= siw_dma_map_page,
	.unmap_page		= siw_dma_unmap_page,
	.map_sg			= siw_dma_map_sg,
	.unmap_sg		= siw_dma_unmap_sg,
	.dma_address		= siw_dma_address,
	.dma_len		= siw_dma_len,
	.sync_single_for_cpu	= siw_sync_single_for_cpu,
	.sync_single_for_device	= siw_sync_single_for_device,
	.alloc_coherent		= siw_dma_alloc_coherent,
	.free_coherent		= siw_dma_free_coherent
};

static void *siw_dma_generic_alloc_coherent(struct device *dev, size_t size,
					    dma_addr_t *dma_handle, gfp_t gfp)
{
	return siw_dma_alloc_coherent(NULL, size, dma_handle, gfp);
}

static void siw_dma_generic_free_coherent(struct device *dev, size_t size,
					  void *vaddr, dma_addr_t dma_handle)
{
	siw_dma_free_coherent(NULL, size, vaddr, dma_handle);
}

static dma_addr_t siw_dma_generic_map_page(struct device *dev,
					   struct page *page,
					   unsigned long offset,
					   size_t size,
					   enum dma_data_direction dir,
					   struct dma_attrs *attrs)
{
	return siw_dma_map_page(NULL, page, offset, size, dir);
}

static void siw_dma_generic_unmap_page(struct device *dev,
				       dma_addr_t handle,
				       size_t size,
				       enum dma_data_direction dir,
				       struct dma_attrs *attrs)
{
	siw_dma_unmap_page(NULL, handle, size, dir);
}

static int siw_dma_generic_map_sg(struct device *dev, struct scatterlist *sg,
				  int nents, enum dma_data_direction dir,
				  struct dma_attrs *attrs)
{
	return siw_dma_map_sg(NULL, sg, nents, dir);
}

static void siw_dma_generic_unmap_sg(struct device *dev,
				    struct scatterlist *sg,
				    int nents,
				    enum dma_data_direction dir,
				    struct dma_attrs *attrs)
{
	siw_dma_unmap_sg(NULL, sg, nents, dir);
}

static void siw_generic_sync_single_for_cpu(struct device *dev,
					    dma_addr_t dma_handle,
					    size_t size,
					    enum dma_data_direction dir)
{
	siw_sync_single_for_cpu(NULL, dma_handle, size, dir);
}


static void siw_generic_sync_single_for_device(struct device *dev,
					       dma_addr_t dma_handle,
					       size_t size,
					       enum dma_data_direction dir)
{
	siw_sync_single_for_device(NULL, dma_handle, size, dir);
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
	return siw_mapping_error(NULL, dma_addr);
}

static int siw_dma_generic_supported(struct device *dev, u64 mask)
{
	return 1;
}

static int siw_dma_generic_set_mask(struct device *dev, u64 mask)
{
	if (!dev->dma_mask || !dma_supported(dev, mask))
		return -EIO;

	*dev->dma_mask = mask;

	return 0;
}

struct dma_map_ops siw_dma_generic_ops = {
	.alloc_coherent		= siw_dma_generic_alloc_coherent,
	.free_coherent		= siw_dma_generic_free_coherent,
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
	.set_dma_mask		= siw_dma_generic_set_mask,
	.is_phys		= 1
};
