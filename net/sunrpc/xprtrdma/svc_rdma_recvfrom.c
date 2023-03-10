// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (c) 2016-2018 Oracle. All rights reserved.
 * Copyright (c) 2014 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2005-2006 Network Appliance, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the BSD-type
 * license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *      Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 *      Neither the name of the Network Appliance, Inc. nor the names of
 *      its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Tom Tucker <tom@opengridcomputing.com>
 */

/* Operation
 *
 * The main entry point is svc_rdma_recvfrom. This is called from
 * svc_recv when the transport indicates there is incoming data to
 * be read. "Data Ready" is signaled when an RDMA Receive completes,
 * or when a set of RDMA Reads complete.
 *
 * An svc_rqst is passed in. This structure contains an array of
 * free pages (rq_pages) that will contain the incoming RPC message.
 *
 * Short messages are moved directly into svc_rqst::rq_arg, and
 * the RPC Call is ready to be processed by the Upper Layer.
 * svc_rdma_recvfrom returns the length of the RPC Call message,
 * completing the reception of the RPC Call.
 *
 * However, when an incoming message has Read chunks,
 * svc_rdma_recvfrom must post RDMA Reads to pull the RPC Call's
 * data payload from the client. svc_rdma_recvfrom sets up the
 * RDMA Reads using pages in svc_rqst::rq_pages, which are
 * transferred to an svc_rdma_recv_ctxt for the duration of the
 * I/O. svc_rdma_recvfrom then returns zero, since the RPC message
 * is still not yet ready.
 *
 * When the Read chunk payloads have become available on the
 * server, "Data Ready" is raised again, and svc_recv calls
 * svc_rdma_recvfrom again. This second call may use a different
 * svc_rqst than the first one, thus any information that needs
 * to be preserved across these two calls is kept in an
 * svc_rdma_recv_ctxt.
 *
 * The second call to svc_rdma_recvfrom performs final assembly
 * of the RPC Call message, using the RDMA Read sink pages kept in
 * the svc_rdma_recv_ctxt. The xdr_buf is copied from the
 * svc_rdma_recv_ctxt to the second svc_rqst. The second call returns
 * the length of the completed RPC Call message.
 *
 * Page Management
 *
 * Pages under I/O must be transferred from the first svc_rqst to an
 * svc_rdma_recv_ctxt before the first svc_rdma_recvfrom call returns.
 *
 * The first svc_rqst supplies pages for RDMA Reads. These are moved
 * from rqstp::rq_pages into ctxt::pages. The consumed elements of
 * the rq_pages array are set to NULL and refilled with the first
 * svc_rdma_recvfrom call returns.
 *
 * During the second svc_rdma_recvfrom call, RDMA Read sink pages
 * are transferred from the svc_rdma_recv_ctxt to the second svc_rqst
 * (see rdma_read_complete() below).
 */

#include <linux/spinlock.h>
#include <asm/unaligned.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

#include <linux/sunrpc/xdr.h>
#include <linux/sunrpc/debug.h>
#include <linux/sunrpc/rpc_rdma.h>
#include <linux/sunrpc/svc_rdma.h>

#include "xprt_rdma.h"
#ifdef HAVE_TRACE_RPCRDMA_H
#include <trace/events/rpcrdma.h>
#endif

#define RPCDBG_FACILITY	RPCDBG_SVCXPRT

static void svc_rdma_wc_receive(struct ib_cq *cq, struct ib_wc *wc);

static inline struct svc_rdma_recv_ctxt *
svc_rdma_next_recv_ctxt(struct list_head *list)
{
	return list_first_entry_or_null(list, struct svc_rdma_recv_ctxt,
					rc_list);
}

#ifdef HAVE_SVC_FILL_WRITE_VECTOR
static void svc_rdma_recv_cid_init(struct svcxprt_rdma *rdma,
				   struct rpc_rdma_cid *cid)
{
	cid->ci_queue_id = rdma->sc_rq_cq->res.id;
	cid->ci_completion_id = atomic_inc_return(&rdma->sc_completion_ids);
}

static struct svc_rdma_recv_ctxt *
svc_rdma_recv_ctxt_alloc(struct svcxprt_rdma *rdma)
{
	struct svc_rdma_recv_ctxt *ctxt;
	dma_addr_t addr;
	void *buffer;

	ctxt = kmalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		goto fail0;
	buffer = kmalloc(rdma->sc_max_req_size, GFP_KERNEL);
	if (!buffer)
		goto fail1;
	addr = ib_dma_map_single(rdma->sc_pd->device, buffer,
				 rdma->sc_max_req_size, DMA_FROM_DEVICE);
	if (ib_dma_mapping_error(rdma->sc_pd->device, addr))
		goto fail2;

	svc_rdma_recv_cid_init(rdma, &ctxt->rc_cid);

	ctxt->rc_recv_wr.next = NULL;
	ctxt->rc_recv_wr.wr_cqe = &ctxt->rc_cqe;
	ctxt->rc_recv_wr.sg_list = &ctxt->rc_recv_sge;
	ctxt->rc_recv_wr.num_sge = 1;
	ctxt->rc_cqe.done = svc_rdma_wc_receive;
	ctxt->rc_recv_sge.addr = addr;
	ctxt->rc_recv_sge.length = rdma->sc_max_req_size;
	ctxt->rc_recv_sge.lkey = rdma->sc_pd->local_dma_lkey;
	ctxt->rc_recv_buf = buffer;
	ctxt->rc_temp = false;
	return ctxt;

fail2:
	kfree(buffer);
fail1:
	kfree(ctxt);
fail0:
	return NULL;
}

static void svc_rdma_recv_ctxt_destroy(struct svcxprt_rdma *rdma,
				       struct svc_rdma_recv_ctxt *ctxt)
{
	ib_dma_unmap_single(rdma->sc_pd->device, ctxt->rc_recv_sge.addr,
			    ctxt->rc_recv_sge.length, DMA_FROM_DEVICE);
	kfree(ctxt->rc_recv_buf);
	kfree(ctxt);
}
#endif

/**
 * svc_rdma_recv_ctxts_destroy - Release all recv_ctxt's for an xprt
 * @rdma: svcxprt_rdma being torn down
 *
 */
void svc_rdma_recv_ctxts_destroy(struct svcxprt_rdma *rdma)
{
	struct svc_rdma_recv_ctxt *ctxt;
#ifdef HAVE_SVC_FILL_WRITE_VECTOR
	struct llist_node *node;

	while ((node = llist_del_first(&rdma->sc_recv_ctxts))) {
		ctxt = llist_entry(node, struct svc_rdma_recv_ctxt, rc_node);
		svc_rdma_recv_ctxt_destroy(rdma, ctxt);
#else
	while ((ctxt = svc_rdma_next_recv_ctxt(&rdma->sc_recv_ctxts))) {
		list_del(&ctxt->rc_list);
		kfree(ctxt);
#endif
	}
}

static struct svc_rdma_recv_ctxt *
svc_rdma_recv_ctxt_get(struct svcxprt_rdma *rdma)
{
	struct svc_rdma_recv_ctxt *ctxt;
#ifdef HAVE_SVC_FILL_WRITE_VECTOR
	struct llist_node *node;

	node = llist_del_first(&rdma->sc_recv_ctxts);
	if (!node)
		goto out_empty;
	ctxt = llist_entry(node, struct svc_rdma_recv_ctxt, rc_node);
#else
	spin_lock(&rdma->sc_recv_lock);
	ctxt = svc_rdma_next_recv_ctxt(&rdma->sc_recv_ctxts);
	if (!ctxt)
		goto out_empty;
	list_del(&ctxt->rc_list);
	spin_unlock(&rdma->sc_recv_lock);
#endif

out:
#ifndef HAVE_SVC_FILL_WRITE_VECTOR
	ctxt->rc_recv_wr.num_sge = 0;
#endif
	ctxt->rc_page_count = 0;
	ctxt->rc_read_payload_length = 0;
	return ctxt;

out_empty:
#ifdef HAVE_SVC_FILL_WRITE_VECTOR
	ctxt = svc_rdma_recv_ctxt_alloc(rdma);
#else
	spin_unlock(&rdma->sc_recv_lock);

	ctxt = kmalloc(sizeof(*ctxt), GFP_KERNEL);
#endif
	if (!ctxt)
		return NULL;
	goto out;
}

#ifndef HAVE_SVC_FILL_WRITE_VECTOR
static void svc_rdma_recv_ctxt_unmap(struct svcxprt_rdma *rdma,
				     struct svc_rdma_recv_ctxt *ctxt)
{
	struct ib_device *device = rdma->sc_cm_id->device;
	int i;

	for (i = 0; i < ctxt->rc_recv_wr.num_sge; i++)
		ib_dma_unmap_page(device,
				  ctxt->rc_sges[i].addr,
				  ctxt->rc_sges[i].length,
				  DMA_FROM_DEVICE);
}
#endif

/**
 * svc_rdma_recv_ctxt_put - Return recv_ctxt to free list
 * @rdma: controlling svcxprt_rdma
 * @ctxt: object to return to the free list
 *
 */
void svc_rdma_recv_ctxt_put(struct svcxprt_rdma *rdma,
			    struct svc_rdma_recv_ctxt *ctxt)
{
	unsigned int i;

	for (i = 0; i < ctxt->rc_page_count; i++)
		put_page(ctxt->rc_pages[i]);

#ifdef HAVE_SVC_FILL_WRITE_VECTOR
	if (!ctxt->rc_temp)
		llist_add(&ctxt->rc_node, &rdma->sc_recv_ctxts);
	else
		svc_rdma_recv_ctxt_destroy(rdma, ctxt);
#else
	spin_lock(&rdma->sc_recv_lock);
	list_add(&ctxt->rc_list, &rdma->sc_recv_ctxts);
	spin_unlock(&rdma->sc_recv_lock);
#endif
}

#ifdef HAVE_SVC_RDMA_RELEASE_RQST
/**
 * svc_rdma_release_rqst - Release transport-specific per-rqst resources
 * @rqstp: svc_rqst being released
 *
 * Ensure that the recv_ctxt is released whether or not a Reply
 * was sent. For example, the client could close the connection,
 * or svc_process could drop an RPC, before the Reply is sent.
 */
void svc_rdma_release_rqst(struct svc_rqst *rqstp)
{
	struct svc_rdma_recv_ctxt *ctxt = rqstp->rq_xprt_ctxt;
	struct svc_xprt *xprt = rqstp->rq_xprt;
	struct svcxprt_rdma *rdma =
		container_of(xprt, struct svcxprt_rdma, sc_xprt);

	rqstp->rq_xprt_ctxt = NULL;
	if (ctxt)
		svc_rdma_recv_ctxt_put(rdma, ctxt);
}
#endif

#ifdef HAVE_SVC_FILL_WRITE_VECTOR
static int __svc_rdma_post_recv(struct svcxprt_rdma *rdma,
				struct svc_rdma_recv_ctxt *ctxt)
{
	int ret;
#else
static int svc_rdma_post_recv(struct svcxprt_rdma *rdma)
{
	struct ib_device *device = rdma->sc_cm_id->device;
	struct svc_rdma_recv_ctxt *ctxt;
	int sge_no, buflen, ret;
	struct page *page;
	dma_addr_t pa;

	ctxt = svc_rdma_recv_ctxt_get(rdma);
	if (!ctxt)
		return -ENOMEM;

	buflen = 0;
	ctxt->rc_cqe.done = svc_rdma_wc_receive;
	for (sge_no = 0; buflen < rdma->sc_max_req_size; sge_no++) {
		if (sge_no >= rdma->sc_max_send_sges) {
			pr_err("svcrdma: Too many sges (%d)\n", sge_no);
			goto err_put_ctxt;
		}

		page = alloc_page(GFP_KERNEL);
		if (!page)
			goto err_put_ctxt;
		ctxt->rc_pages[sge_no] = page;
		ctxt->rc_page_count++;

		pa = ib_dma_map_page(device, ctxt->rc_pages[sge_no],
				     0, PAGE_SIZE, DMA_FROM_DEVICE);
		if (ib_dma_mapping_error(device, pa))
			goto err_put_ctxt;
		ctxt->rc_sges[sge_no].addr = pa;
		ctxt->rc_sges[sge_no].length = PAGE_SIZE;
		ctxt->rc_sges[sge_no].lkey = rdma->sc_pd->local_dma_lkey;
		ctxt->rc_recv_wr.num_sge++;

		buflen += PAGE_SIZE;
	}
	ctxt->rc_recv_wr.next = NULL;
	ctxt->rc_recv_wr.sg_list = &ctxt->rc_sges[0];
	ctxt->rc_recv_wr.wr_cqe = &ctxt->rc_cqe;
#endif

#ifdef HAVE_TRACE_RPCRDMA_H
	trace_svcrdma_post_recv(ctxt);
#endif
	ret = ib_post_recv(rdma->sc_qp, &ctxt->rc_recv_wr, NULL);
	if (ret)
		goto err_post;
	return 0;

#ifndef HAVE_SVC_FILL_WRITE_VECTOR
err_put_ctxt:
	svc_rdma_recv_ctxt_unmap(rdma, ctxt);
	svc_rdma_recv_ctxt_put(rdma, ctxt);
	return -ENOMEM;
#endif

err_post:
#ifndef HAVE_SVC_FILL_WRITE_VECTOR
	svc_rdma_recv_ctxt_unmap(rdma, ctxt);
#endif
#ifdef HAVE_TRACE_RPCRDMA_H
	trace_svcrdma_rq_post_err(rdma, ret);
#endif
	svc_rdma_recv_ctxt_put(rdma, ctxt);
	return ret;
}

#ifdef HAVE_SVC_FILL_WRITE_VECTOR
static int svc_rdma_post_recv(struct svcxprt_rdma *rdma)
{
	struct svc_rdma_recv_ctxt *ctxt;

	if (test_bit(XPT_CLOSE, &rdma->sc_xprt.xpt_flags))
		return 0;
	ctxt = svc_rdma_recv_ctxt_get(rdma);
	if (!ctxt)
		return -ENOMEM;
	return __svc_rdma_post_recv(rdma, ctxt);
}
#endif

/**
 * svc_rdma_post_recvs - Post initial set of Recv WRs
 * @rdma: fresh svcxprt_rdma
 *
 * Returns true if successful, otherwise false.
 */
bool svc_rdma_post_recvs(struct svcxprt_rdma *rdma)
{
#ifdef HAVE_SVC_FILL_WRITE_VECTOR
	struct svc_rdma_recv_ctxt *ctxt;
#endif
	unsigned int i;
	int ret;

	for (i = 0; i < rdma->sc_max_requests; i++) {
#ifdef HAVE_SVC_FILL_WRITE_VECTOR
		ctxt = svc_rdma_recv_ctxt_get(rdma);
		if (!ctxt)
			return false;
		ctxt->rc_temp = true;
		ret = __svc_rdma_post_recv(rdma, ctxt);
#else
		ret = svc_rdma_post_recv(rdma);
#endif
		if (ret)
			return false;
	}
	return true;
}

/**
 * svc_rdma_wc_receive - Invoked by RDMA provider for each polled Receive WC
 * @cq: Completion Queue context
 * @wc: Work Completion object
 *
 * NB: The svc_xprt/svcxprt_rdma is pinned whenever it's possible that
 * the Receive completion handler could be running.
 */
static void svc_rdma_wc_receive(struct ib_cq *cq, struct ib_wc *wc)
{
	struct svcxprt_rdma *rdma = cq->cq_context;
	struct ib_cqe *cqe = wc->wr_cqe;
	struct svc_rdma_recv_ctxt *ctxt;

	/* WARNING: Only wc->wr_cqe and wc->status are reliable */
	ctxt = container_of(cqe, struct svc_rdma_recv_ctxt, rc_cqe);
#ifndef HAVE_SVC_FILL_WRITE_VECTOR
	svc_rdma_recv_ctxt_unmap(rdma, ctxt);
#endif

#ifdef HAVE_TRACE_RPCRDMA_H
	trace_svcrdma_wc_receive(wc, &ctxt->rc_cid);
#endif
	if (wc->status != IB_WC_SUCCESS)
		goto flushed;

	if (svc_rdma_post_recv(rdma))
		goto post_err;

	/* All wc fields are now known to be valid */
	ctxt->rc_byte_len = wc->byte_len;
#ifdef HAVE_SVC_FILL_WRITE_VECTOR
	ib_dma_sync_single_for_cpu(rdma->sc_pd->device,
				   ctxt->rc_recv_sge.addr,
				   wc->byte_len, DMA_FROM_DEVICE);
#endif

	spin_lock(&rdma->sc_rq_dto_lock);
	list_add_tail(&ctxt->rc_list, &rdma->sc_rq_dto_q);
	/* Note the unlock pairs with the smp_rmb in svc_xprt_ready: */
	set_bit(XPT_DATA, &rdma->sc_xprt.xpt_flags);
	spin_unlock(&rdma->sc_rq_dto_lock);
	if (!test_bit(RDMAXPRT_CONN_PENDING, &rdma->sc_flags))
		svc_xprt_enqueue(&rdma->sc_xprt);
	return;

flushed:
post_err:
	svc_rdma_recv_ctxt_put(rdma, ctxt);
	set_bit(XPT_CLOSE, &rdma->sc_xprt.xpt_flags);
	svc_xprt_enqueue(&rdma->sc_xprt);
}

/**
 * svc_rdma_flush_recv_queues - Drain pending Receive work
 * @rdma: svcxprt_rdma being shut down
 *
 */
void svc_rdma_flush_recv_queues(struct svcxprt_rdma *rdma)
{
	struct svc_rdma_recv_ctxt *ctxt;

	while ((ctxt = svc_rdma_next_recv_ctxt(&rdma->sc_read_complete_q))) {
		list_del(&ctxt->rc_list);
		svc_rdma_recv_ctxt_put(rdma, ctxt);
	}
	while ((ctxt = svc_rdma_next_recv_ctxt(&rdma->sc_rq_dto_q))) {
		list_del(&ctxt->rc_list);
		svc_rdma_recv_ctxt_put(rdma, ctxt);
	}
}

static void svc_rdma_build_arg_xdr(struct svc_rqst *rqstp,
				   struct svc_rdma_recv_ctxt *ctxt)
{
#ifdef HAVE_SVC_FILL_WRITE_VECTOR
	struct xdr_buf *arg = &rqstp->rq_arg;

	arg->head[0].iov_base = ctxt->rc_recv_buf;
	arg->head[0].iov_len = ctxt->rc_byte_len;
	arg->tail[0].iov_base = NULL;
	arg->tail[0].iov_len = 0;
	arg->page_len = 0;
	arg->page_base = 0;
	arg->buflen = ctxt->rc_byte_len;
	arg->len = ctxt->rc_byte_len;
#else
	struct page *page;
	int sge_no;
	u32 len;

	/* The reply path assumes the Call's transport header resides
	 * in rqstp->rq_pages[0].
	 */
	page = ctxt->rc_pages[0];
	put_page(rqstp->rq_pages[0]);
	rqstp->rq_pages[0] = page;

	/* Set up the XDR head */
	rqstp->rq_arg.head[0].iov_base = page_address(page);
	rqstp->rq_arg.head[0].iov_len =
		min_t(size_t, ctxt->rc_byte_len, ctxt->rc_sges[0].length);
	rqstp->rq_arg.len = ctxt->rc_byte_len;
	rqstp->rq_arg.buflen = ctxt->rc_byte_len;

	/* Compute bytes past head in the SGL */
	len = ctxt->rc_byte_len - rqstp->rq_arg.head[0].iov_len;

	/* If data remains, store it in the pagelist */
	rqstp->rq_arg.page_len = len;
	rqstp->rq_arg.page_base = 0;

	sge_no = 1;
	while (len && sge_no < ctxt->rc_recv_wr.num_sge) {
		page = ctxt->rc_pages[sge_no];
		put_page(rqstp->rq_pages[sge_no]);
		rqstp->rq_pages[sge_no] = page;
		len -= min_t(u32, len, ctxt->rc_sges[sge_no].length);
		sge_no++;
	}
	ctxt->rc_hdr_count = sge_no;
	rqstp->rq_respages = &rqstp->rq_pages[sge_no];
	rqstp->rq_next_page = rqstp->rq_respages + 1;

	/* If not all pages were used from the SGL, free the remaining ones */
	while (sge_no < ctxt->rc_recv_wr.num_sge) {
		page = ctxt->rc_pages[sge_no++];
		put_page(page);
	}

	/* @ctxt's pages have all been released or moved to @rqstp->rq_pages.
	 */
	ctxt->rc_page_count = 0;

	/* Set up tail */
	rqstp->rq_arg.tail[0].iov_base = NULL;
	rqstp->rq_arg.tail[0].iov_len = 0;
#endif
}

/* This accommodates the largest possible Write chunk.
 */
#define MAX_BYTES_WRITE_CHUNK ((u32)(RPCSVC_MAXPAGES << PAGE_SHIFT))

/* This accommodates the largest possible Position-Zero
 * Read chunk or Reply chunk.
 */
#define MAX_BYTES_SPECIAL_CHUNK ((u32)((RPCSVC_MAXPAGES + 2) << PAGE_SHIFT))

/* Sanity check the Read list.
 *
 * Implementation limits:
 * - This implementation supports only one Read chunk.
 *
 * Sanity checks:
 * - Read list does not overflow Receive buffer.
 * - Segment size limited by largest NFS data payload.
 *
 * The segment count is limited to how many segments can
 * fit in the transport header without overflowing the
 * buffer. That's about 40 Read segments for a 1KB inline
 * threshold.
 *
 * Return values:
 *       %true: Read list is valid. @rctxt's xdr_stream is updated
 *		to point to the first byte past the Read list.
 *      %false: Read list is corrupt. @rctxt's xdr_stream is left
 *		in an unknown state.
 */
static bool xdr_check_read_list(struct svc_rdma_recv_ctxt *rctxt)
{
	u32 position, len;
	bool first;
	__be32 *p;

	p = xdr_inline_decode(&rctxt->rc_stream, sizeof(*p));
	if (!p)
		return false;

	len = 0;
	first = true;
	while (xdr_item_is_present(p)) {
		p = xdr_inline_decode(&rctxt->rc_stream,
				      rpcrdma_readseg_maxsz * sizeof(*p));
		if (!p)
			return false;

		if (first) {
			position = be32_to_cpup(p);
			first = false;
		} else if (be32_to_cpup(p) != position) {
			return false;
		}
		p += 2;
		len += be32_to_cpup(p);

		p = xdr_inline_decode(&rctxt->rc_stream, sizeof(*p));
		if (!p)
			return false;
	}
	return len <= MAX_BYTES_SPECIAL_CHUNK;
}

/* The segment count is limited to how many segments can
 * fit in the transport header without overflowing the
 * buffer. That's about 60 Write segments for a 1KB inline
 * threshold.
 */
static bool xdr_check_write_chunk(struct svc_rdma_recv_ctxt *rctxt, u32 maxlen)
{
	u32 i, segcount, total;
	__be32 *p;

	p = xdr_inline_decode(&rctxt->rc_stream, sizeof(*p));
	if (!p)
		return false;
	segcount = be32_to_cpup(p);

	total = 0;
	for (i = 0; i < segcount; i++) {
		u32 handle, length;
		u64 offset;

		p = xdr_inline_decode(&rctxt->rc_stream,
				      rpcrdma_segment_maxsz * sizeof(*p));
		if (!p)
			return false;

		xdr_decode_rdma_segment(p, &handle, &length, &offset);
#ifdef HAVE_TRACE_RPCRDMA_H
		trace_svcrdma_decode_wseg(handle, length, offset);
#endif

		total += length;
	}
	return total <= maxlen;
}

/* Sanity check the Write list.
 *
 * Implementation limits:
 * - This implementation currently supports only one Write chunk.
 *
 * Sanity checks:
 * - Write list does not overflow Receive buffer.
 * - Chunk size limited by largest NFS data payload.
 *
 * Return values:
 *       %true: Write list is valid. @rctxt's xdr_stream is updated
 *		to point to the first byte past the Write list.
 *      %false: Write list is corrupt. @rctxt's xdr_stream is left
 *		in an unknown state.
 */
static bool xdr_check_write_list(struct svc_rdma_recv_ctxt *rctxt)
{
	u32 chcount = 0;
	__be32 *p;

	p = xdr_inline_decode(&rctxt->rc_stream, sizeof(*p));
	if (!p)
		return false;
	rctxt->rc_write_list = p;
	while (xdr_item_is_present(p)) {
		if (!xdr_check_write_chunk(rctxt, MAX_BYTES_WRITE_CHUNK))
			return false;
		++chcount;
		p = xdr_inline_decode(&rctxt->rc_stream, sizeof(*p));
		if (!p)
			return false;
	}
	if (!chcount)
		rctxt->rc_write_list = NULL;
	return chcount < 2;
}

/* Sanity check the Reply chunk.
 *
 * Sanity checks:
 * - Reply chunk does not overflow Receive buffer.
 * - Chunk size limited by largest NFS data payload.
 *
 * Return values:
 *       %true: Reply chunk is valid. @rctxt's xdr_stream is updated
 *		to point to the first byte past the Reply chunk.
 *      %false: Reply chunk is corrupt. @rctxt's xdr_stream is left
 *		in an unknown state.
 */
static bool xdr_check_reply_chunk(struct svc_rdma_recv_ctxt *rctxt)
{
	__be32 *p;

	p = xdr_inline_decode(&rctxt->rc_stream, sizeof(*p));
	if (!p)
		return false;
	rctxt->rc_reply_chunk = NULL;
	if (xdr_item_is_present(p)) {
		if (!xdr_check_write_chunk(rctxt, MAX_BYTES_SPECIAL_CHUNK))
			return false;
		rctxt->rc_reply_chunk = p;
	}
	return true;
}

/* RPC-over-RDMA Version One private extension: Remote Invalidation.
 * Responder's choice: requester signals it can handle Send With
 * Invalidate, and responder chooses one R_key to invalidate.
 *
 * If there is exactly one distinct R_key in the received transport
 * header, set rc_inv_rkey to that R_key. Otherwise, set it to zero.
 *
 * Perform this operation while the received transport header is
 * still in the CPU cache.
 */
static void svc_rdma_get_inv_rkey(struct svcxprt_rdma *rdma,
				  struct svc_rdma_recv_ctxt *ctxt)
{
	__be32 inv_rkey, *p;
	u32 i, segcount;

	ctxt->rc_inv_rkey = 0;

	if (!rdma->sc_snd_w_inv)
		return;

	inv_rkey = xdr_zero;
#ifdef HAVE_SVC_FILL_WRITE_VECTOR
	p = ctxt->rc_recv_buf;
#else
	p = page_address(ctxt->rc_pages[0]);
#endif
	p += rpcrdma_fixed_maxsz;

	/* Read list */
	while (xdr_item_is_present(p++)) {
		p++;	/* position */
		if (inv_rkey == xdr_zero)
			inv_rkey = *p;
		else if (inv_rkey != *p)
			return;
		p += 4;
	}

	/* Write list */
	while (xdr_item_is_present(p++)) {
		segcount = be32_to_cpup(p++);
		for (i = 0; i < segcount; i++) {
			if (inv_rkey == xdr_zero)
				inv_rkey = *p;
			else if (inv_rkey != *p)
				return;
			p += 4;
		}
	}

	/* Reply chunk */
	if (xdr_item_is_present(p++)) {
		segcount = be32_to_cpup(p++);
		for (i = 0; i < segcount; i++) {
			if (inv_rkey == xdr_zero)
				inv_rkey = *p;
			else if (inv_rkey != *p)
				return;
			p += 4;
		}
	}

	ctxt->rc_inv_rkey = be32_to_cpu(inv_rkey);
}

/**
 * svc_rdma_xdr_decode_req - Decode the transport header
 * @rq_arg: xdr_buf containing ingress RPC/RDMA message
 * @rctxt: state of decoding
 *
 * On entry, xdr->head[0].iov_base points to first byte of the
 * RPC-over-RDMA transport header.
 *
 * On successful exit, head[0] points to first byte past the
 * RPC-over-RDMA header. For RDMA_MSG, this is the RPC message.
 *
 * The length of the RPC-over-RDMA header is returned.
 *
 * Assumptions:
 * - The transport header is entirely contained in the head iovec.
 */
static int svc_rdma_xdr_decode_req(struct xdr_buf *rq_arg,
				   struct svc_rdma_recv_ctxt *rctxt)
{
	__be32 *p, *rdma_argp;
	unsigned int hdr_len;

	rdma_argp = rq_arg->head[0].iov_base;
#ifdef HAVE_XDR_INIT_DECODE_RQST_ARG
	xdr_init_decode(&rctxt->rc_stream, rq_arg, rdma_argp, NULL);
#else
	xdr_init_decode(&rctxt->rc_stream, rq_arg, rdma_argp);
#endif

	p = xdr_inline_decode(&rctxt->rc_stream,
			      rpcrdma_fixed_maxsz * sizeof(*p));
	if (unlikely(!p))
		goto out_short;
	p++;
	if (*p != rpcrdma_version)
		goto out_version;
	p += 2;
	switch (*p) {
	case rdma_msg:
		break;
	case rdma_nomsg:
		break;
	case rdma_done:
		goto out_drop;
	case rdma_error:
		goto out_drop;
	default:
		goto out_proc;
	}

	if (!xdr_check_read_list(rctxt))
		goto out_inval;
	if (!xdr_check_write_list(rctxt))
		goto out_inval;
	if (!xdr_check_reply_chunk(rctxt))
		goto out_inval;

	rq_arg->head[0].iov_base = rctxt->rc_stream.p;
	hdr_len = xdr_stream_pos(&rctxt->rc_stream);
	rq_arg->head[0].iov_len -= hdr_len;
	rq_arg->len -= hdr_len;
#ifdef HAVE_TRACE_RPCRDMA_H
	trace_svcrdma_decode_rqst(rctxt, rdma_argp, hdr_len);
#endif
	return hdr_len;

out_short:
#ifdef HAVE_TRACE_RPCRDMA_H
	trace_svcrdma_decode_short_err(rctxt, rq_arg->len);
#endif
	return -EINVAL;

out_version:
#ifdef HAVE_TRACE_RPCRDMA_H
	trace_svcrdma_decode_badvers_err(rctxt, rdma_argp);
#endif
	return -EPROTONOSUPPORT;

out_drop:
#ifdef HAVE_TRACE_RPCRDMA_H
	trace_svcrdma_decode_drop_err(rctxt, rdma_argp);
#endif
	return 0;

out_proc:
#ifdef HAVE_TRACE_RPCRDMA_H
	trace_svcrdma_decode_badproc_err(rctxt, rdma_argp);
#endif
	return -EINVAL;

out_inval:
#ifdef HAVE_TRACE_RPCRDMA_H
	trace_svcrdma_decode_parse_err(rctxt, rdma_argp);
#endif
	return -EINVAL;
}

static void rdma_read_complete(struct svc_rqst *rqstp,
			       struct svc_rdma_recv_ctxt *head)
{
	int page_no;

	/* Move Read chunk pages to rqstp so that they will be released
	 * when svc_process is done with them.
	 */
	for (page_no = 0; page_no < head->rc_page_count; page_no++) {
		put_page(rqstp->rq_pages[page_no]);
		rqstp->rq_pages[page_no] = head->rc_pages[page_no];
	}
	head->rc_page_count = 0;

	/* Point rq_arg.pages past header */
	rqstp->rq_arg.pages = &rqstp->rq_pages[head->rc_hdr_count];
	rqstp->rq_arg.page_len = head->rc_arg.page_len;

	/* rq_respages starts after the last arg page */
	rqstp->rq_respages = &rqstp->rq_pages[page_no];
	rqstp->rq_next_page = rqstp->rq_respages + 1;

	/* Rebuild rq_arg head and tail. */
	rqstp->rq_arg.head[0] = head->rc_arg.head[0];
	rqstp->rq_arg.tail[0] = head->rc_arg.tail[0];
	rqstp->rq_arg.len = head->rc_arg.len;
	rqstp->rq_arg.buflen = head->rc_arg.buflen;
}

static void svc_rdma_send_error(struct svcxprt_rdma *rdma,
				struct svc_rdma_recv_ctxt *rctxt,
				int status)
{
	struct svc_rdma_send_ctxt *sctxt;

	sctxt = svc_rdma_send_ctxt_get(rdma);
	if (!sctxt)
		return;
	svc_rdma_send_error_msg(rdma, sctxt, rctxt, status);
}

/* By convention, backchannel calls arrive via rdma_msg type
 * messages, and never populate the chunk lists. This makes
 * the RPC/RDMA header small and fixed in size, so it is
 * straightforward to check the RPC header's direction field.
 */
static bool svc_rdma_is_backchannel_reply(struct svc_xprt *xprt,
					  __be32 *rdma_resp)
{
	__be32 *p;

	if (!xprt->xpt_bc_xprt)
		return false;

	p = rdma_resp + 3;
	if (*p++ != rdma_msg)
		return false;

	if (*p++ != xdr_zero)
		return false;
	if (*p++ != xdr_zero)
		return false;
	if (*p++ != xdr_zero)
		return false;

	/* XID sanity */
	if (*p++ != *rdma_resp)
		return false;
	/* call direction */
	if (*p == cpu_to_be32(RPC_CALL))
		return false;

	return true;
}

/**
 * svc_rdma_recvfrom - Receive an RPC call
 * @rqstp: request structure into which to receive an RPC Call
 *
 * Returns:
 *	The positive number of bytes in the RPC Call message,
 *	%0 if there were no Calls ready to return,
 *	%-EINVAL if the Read chunk data is too large,
 *	%-ENOMEM if rdma_rw context pool was exhausted,
 *	%-ENOTCONN if posting failed (connection is lost),
 *	%-EIO if rdma_rw initialization failed (DMA mapping, etc).
 *
 * Called in a loop when XPT_DATA is set. XPT_DATA is cleared only
 * when there are no remaining ctxt's to process.
 *
 * The next ctxt is removed from the "receive" lists.
 *
 * - If the ctxt completes a Read, then finish assembling the Call
 *   message and return the number of bytes in the message.
 *
 * - If the ctxt completes a Receive, then construct the Call
 *   message from the contents of the Receive buffer.
 *
 *   - If there are no Read chunks in this message, then finish
 *     assembling the Call message and return the number of bytes
 *     in the message.
 *
 *   - If there are Read chunks in this message, post Read WRs to
 *     pull that payload and return 0.
 */
int svc_rdma_recvfrom(struct svc_rqst *rqstp)
{
	struct svc_xprt *xprt = rqstp->rq_xprt;
	struct svcxprt_rdma *rdma_xprt =
		container_of(xprt, struct svcxprt_rdma, sc_xprt);
	struct svc_rdma_recv_ctxt *ctxt;
	__be32 *p;
	int ret;

#ifdef HAVE_SVC_RDMA_RELEASE_RQST
	rqstp->rq_xprt_ctxt = NULL;
#endif

	spin_lock(&rdma_xprt->sc_rq_dto_lock);
	ctxt = svc_rdma_next_recv_ctxt(&rdma_xprt->sc_read_complete_q);
	if (ctxt) {
		list_del(&ctxt->rc_list);
		spin_unlock(&rdma_xprt->sc_rq_dto_lock);
		rdma_read_complete(rqstp, ctxt);
		goto complete;
	}
	ctxt = svc_rdma_next_recv_ctxt(&rdma_xprt->sc_rq_dto_q);
	if (!ctxt) {
		/* No new incoming requests, terminate the loop */
		clear_bit(XPT_DATA, &xprt->xpt_flags);
		spin_unlock(&rdma_xprt->sc_rq_dto_lock);
		return 0;
	}
	list_del(&ctxt->rc_list);
	spin_unlock(&rdma_xprt->sc_rq_dto_lock);

	atomic_inc(&rdma_stat_recv);

	svc_rdma_build_arg_xdr(rqstp, ctxt);

#ifdef HAVE_SVC_FILL_WRITE_VECTOR
	/* Prevent svc_xprt_release from releasing pages in rq_pages
	 * if we return 0 or an error.
	 */
	rqstp->rq_respages = rqstp->rq_pages;
	rqstp->rq_next_page = rqstp->rq_respages;
#endif

	p = (__be32 *)rqstp->rq_arg.head[0].iov_base;
	ret = svc_rdma_xdr_decode_req(&rqstp->rq_arg, ctxt);
	if (ret < 0)
		goto out_err;
	if (ret == 0)
		goto out_drop;
	rqstp->rq_xprt_hlen = ret;

	if (svc_rdma_is_backchannel_reply(xprt, p))
		goto out_backchannel;

	svc_rdma_get_inv_rkey(rdma_xprt, ctxt);

	p += rpcrdma_fixed_maxsz;
	if (*p != xdr_zero)
		goto out_readchunk;

complete:
	rqstp->rq_xprt_ctxt = ctxt;
	rqstp->rq_prot = IPPROTO_MAX;
	svc_xprt_copy_addrs(rqstp, xprt);
	return rqstp->rq_arg.len;

out_readchunk:
	ret = svc_rdma_recv_read_chunk(rdma_xprt, rqstp, ctxt, p);
	if (ret < 0)
		goto out_postfail;
	return 0;

out_err:
	svc_rdma_send_error(rdma_xprt, ctxt, ret);
	svc_rdma_recv_ctxt_put(rdma_xprt, ctxt);
	return 0;

out_postfail:
	if (ret == -EINVAL)
		svc_rdma_send_error(rdma_xprt, ctxt, ret);
	svc_rdma_recv_ctxt_put(rdma_xprt, ctxt);
	return ret;

out_backchannel:
	svc_rdma_handle_bc_reply(rqstp, ctxt);
out_drop:
	svc_rdma_recv_ctxt_put(rdma_xprt, ctxt);
	return 0;
}
