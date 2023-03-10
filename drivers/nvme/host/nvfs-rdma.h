/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2020 NVIDIA Corporation.
 */

#ifndef NVFS_RDMA_H
#define NVFS_RDMA_H

#define DEV queue->device->dev->dma_device
#define SGL req->data_sgl.sg_table.sgl

static int nvme_rdma_map_sg_inline(struct nvme_rdma_queue *queue,
               struct nvme_rdma_request *req, struct nvme_command *c,
               int count);

static int nvme_rdma_map_sg_single(struct nvme_rdma_queue *queue,
               struct nvme_rdma_request *req, struct nvme_command *c);


static int nvme_rdma_map_sg_fr(struct nvme_rdma_queue *queue,
               struct nvme_rdma_request *req, struct nvme_command *c,
               int count);

static bool nvme_rdma_nvfs_unmap_data(struct nvme_rdma_queue *queue,
		struct request *rq)

{
	struct nvme_rdma_request *req = blk_mq_rq_to_pdu(rq);
	enum dma_data_direction dma_dir = rq_dma_dir(rq);
	int count;

	if (!blk_integrity_rq(rq) && nvfs_ops != NULL) {
		count = nvfs_ops->nvfs_dma_unmap_sg(DEV, SGL, req->data_sgl.nents,
				dma_dir);
		if (count) {
			nvfs_put_ops();
#ifdef HAVE_SG_ALLOC_TABLE_CHAINED_NENTS_FIRST_CHUNK_PARAM
			sg_free_table_chained(&req->data_sgl.sg_table, NVME_INLINE_SG_CNT);
#else
			sg_free_table_chained(&req->data_sgl.sg_table, true);
#endif

			return true;
		}
	}
	return false;
}

static int nvme_rdma_nvfs_map_data(struct nvme_rdma_queue *queue, struct request *rq,
		struct nvme_command *cmnd, bool *is_nvfs_io)
{
	struct nvme_rdma_request *req = blk_mq_rq_to_pdu(rq);
	struct nvme_rdma_device *dev = queue->device;
	enum dma_data_direction dma_dir = rq_dma_dir(rq);
	int count, ret = 0;

	*is_nvfs_io = false;
	count = 0;
	if (!blk_integrity_rq(rq) && nvfs_get_ops()) {
		// associates bio pages to scatterlist
		count = nvfs_ops->nvfs_blk_rq_map_sg(rq->q, rq , SGL);
		if (!count) {
			nvfs_put_ops();
			return 0; // fall to cpu path
		}

		*is_nvfs_io = true;
		if (unlikely((count == NVFS_IO_ERR))) {
			nvfs_put_ops();
			pr_err("%s: failed to map sg_nents=:%d\n", __func__, req->data_sgl.nents);
			ret = -EIO;
			goto out_free_table;
		}
		req->data_sgl.nents = count;

		count = nvfs_ops->nvfs_dma_map_sg_attrs(DEV,
				SGL,
				req->data_sgl.nents,
				dma_dir,
				DMA_ATTR_NO_WARN);

		if (unlikely((count == NVFS_IO_ERR))) {
			nvfs_put_ops();
			ret = -EIO;
			goto out_free_table;
		}

		if (unlikely(count == NVFS_CPU_REQ)) {
			nvfs_put_ops();
			BUG();
			return -EIO;
		}

		if (count <= dev->num_inline_segments) {
			if (rq_data_dir(rq) == WRITE && nvme_rdma_queue_idx(queue) &&
					queue->ctrl->use_inline_data &&
#ifdef HAVE_BLK_RQ_NR_PAYLOAD_BYTES
					blk_rq_payload_bytes(rq) <=
#else
					nvme_map_len(rq) <=
#endif
						nvme_rdma_inline_data_size(queue)) {
				ret = nvme_rdma_map_sg_inline(queue, req, cmnd, count);
				goto out;
			}

			if (count == 1 && dev->pd->flags & IB_PD_UNSAFE_GLOBAL_RKEY) {
				ret = nvme_rdma_map_sg_single(queue, req, cmnd);
				goto out;
			}
		}

		ret = nvme_rdma_map_sg_fr(queue, req, cmnd, count);
out:
		if (unlikely(ret)) {
			nvme_rdma_nvfs_unmap_data(queue, rq);
		}

		return ret;
	} else {
		// Fall to CPU path
		return 0;
	}

out_free_table:
#ifdef HAVE_SG_ALLOC_TABLE_CHAINED_NENTS_FIRST_CHUNK_PARAM
	sg_free_table_chained(&req->data_sgl.sg_table, NVME_INLINE_SG_CNT);
#else
	sg_free_table_chained(&req->data_sgl.sg_table, true);
#endif
	return ret;
}

#endif
