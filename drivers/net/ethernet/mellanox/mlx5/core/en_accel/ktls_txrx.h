/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2020, Mellanox Technologies inc. All rights reserved. */

#ifndef __MLX5E_KTLS_TXRX_H__
#define __MLX5E_KTLS_TXRX_H__

#ifdef CONFIG_MLX5_EN_TLS

#include <net/tls.h>
#include "en.h"
#include "en/txrx.h"

struct mlx5e_accel_tx_tls_state {
	u32 tls_tisn;
};

#ifdef HAVE_KTLS_STRUCTS
u16 mlx5e_ktls_get_stop_room(struct mlx5e_params *params);

bool mlx5e_ktls_handle_tx_skb(struct tls_context *tls_ctx, struct mlx5e_txqsq *sq,
			      struct sk_buff *skb, int datalen,
			      struct mlx5e_accel_tx_tls_state *state);
#else
static inline
u16 mlx5e_ktls_get_stop_room(struct mlx5e_params *params)
{
	return 0;
}

static inline
bool mlx5e_ktls_handle_tx_skb(struct tls_context *tls_ctx, struct mlx5e_txqsq *sq,
			      struct sk_buff *skb, int datalen,
			      struct mlx5e_accel_tx_tls_state *state)
{
	return false;
}
#endif

#ifdef HAVE_KTLS_RX_SUPPORT
void mlx5e_ktls_handle_rx_skb(struct mlx5e_rq *rq, struct sk_buff *skb,
			      struct mlx5_cqe64 *cqe, u32 *cqe_bcnt);

void mlx5e_ktls_handle_ctx_completion(struct mlx5e_icosq_wqe_info *wi);
void mlx5e_ktls_handle_get_psv_completion(struct mlx5e_icosq_wqe_info *wi,
					  struct mlx5e_icosq *sq);
#else
static inline
void mlx5e_ktls_handle_rx_skb(struct mlx5e_rq *rq, struct sk_buff *skb,
			      struct mlx5_cqe64 *cqe, u32 *cqe_bcnt)
{
}

static inline
void mlx5e_ktls_handle_ctx_completion(struct mlx5e_icosq_wqe_info *wi)
{
}

static inline
void mlx5e_ktls_handle_get_psv_completion(struct mlx5e_icosq_wqe_info *wi,
					  struct mlx5e_icosq *sq)
{
}
#endif

#ifdef HAVE_KTLS_STRUCTS
void mlx5e_ktls_tx_handle_resync_dump_comp(struct mlx5e_txqsq *sq,
					   struct mlx5e_tx_wqe_info *wi,
					   u32 *dma_fifo_cc);
static inline bool
mlx5e_ktls_tx_try_handle_resync_dump_comp(struct mlx5e_txqsq *sq,
					  struct mlx5e_tx_wqe_info *wi,
					  u32 *dma_fifo_cc)
{
	if (unlikely(wi->resync_dump_frag_page)) {
		mlx5e_ktls_tx_handle_resync_dump_comp(sq, wi, dma_fifo_cc);
		return true;
	}
	return false;
}
#else
static inline bool
mlx5e_ktls_tx_try_handle_resync_dump_comp(struct mlx5e_txqsq *sq,
					  struct mlx5e_tx_wqe_info *wi,
					  u32 *dma_fifo_cc)
{
	return false;
}
#endif /* HAVE_KTLS_STRUCTS */

#else

static inline bool
mlx5e_ktls_tx_try_handle_resync_dump_comp(struct mlx5e_txqsq *sq,
					  struct mlx5e_tx_wqe_info *wi,
					  u32 *dma_fifo_cc)
{
	return false;
}

#endif /* CONFIG_MLX5_EN_TLS */

#endif /* __MLX5E_TLS_TXRX_H__ */
