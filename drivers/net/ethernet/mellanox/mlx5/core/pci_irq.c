// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2019 Mellanox Technologies. */

#include <linux/interrupt.h>
#include <linux/notifier.h>
#include <linux/module.h>
#include <linux/mlx5/driver.h>
#include "mlx5_core.h"
#include "mlx5_irq.h"
#include "sf/sf.h"
#ifdef CONFIG_RFS_ACCEL
#include <linux/cpu_rmap.h>
#endif

#define MLX5_MAX_IRQ_NAME (32)
#define MLX5_FW_RESERVED_EQS 16

/* max irq_index is 2048. three chars */
#define MLX5_MAX_IRQ_IDX_CHARS (4)

#define MLX5_SFS_PER_CTRL_IRQ 64
#define MLX5_IRQ_CTRL_SF_MAX 8
/* min num of vectores for SFs to be enabled */
#define MLX5_IRQ_VEC_COMP_BASE_SF 2

#define MLX5_EQ_SHARE_IRQ_MAX_COMP (8)
#define MLX5_EQ_SHARE_IRQ_MAX_CTRL (UINT_MAX)
#define MLX5_EQ_SHARE_IRQ_MIN_COMP (1)
#define MLX5_EQ_SHARE_IRQ_MIN_CTRL (4)
#define MLX5_EQ_REFS_PER_IRQ (2)

struct mlx5_irq {
	u32 index;
	struct atomic_notifier_head nh;
	cpumask_var_t mask;
	char name[MLX5_MAX_IRQ_NAME];
	struct kref kref;
	int irqn;
	struct mlx5_irq_pool *pool;
};

struct mlx5_irq_pool {
	char name[MLX5_MAX_IRQ_NAME - MLX5_MAX_IRQ_IDX_CHARS];
	struct xa_limit xa_num_irqs;
	struct mutex lock; /* sync IRQs creations */
	struct xarray irqs;
	u32 max_threshold;
	u32 min_threshold;
	struct mlx5_core_dev *dev;
};

struct mlx5_irq_table {
	struct mlx5_irq_pool *pf_pool;
	struct mlx5_irq_pool *sf_ctrl_pool;
	struct mlx5_irq_pool *sf_comp_pool;
	atomic_t *cpus;
};

/**
 * mlx5_get_default_msix_vec_count - Get the default number of MSI-X vectors
 *                                   to be ssigned to each VF.
 * @dev: PF to work on
 * @num_vfs: Number of enabled VFs
 */
int mlx5_get_default_msix_vec_count(struct mlx5_core_dev *dev, int num_vfs)
{
	int num_vf_msix, min_msix, max_msix;

	num_vf_msix = MLX5_CAP_GEN_MAX(dev, num_total_dynamic_vf_msix);
	if (!num_vf_msix)
		return 0;

	min_msix = MLX5_CAP_GEN(dev, min_dynamic_vf_msix_table_size);
	max_msix = MLX5_CAP_GEN(dev, max_dynamic_vf_msix_table_size);

	/* Limit maximum number of MSI-X vectors so the default configuration
	 * has some available in the pool. This will allow the user to increase
	 * the number of vectors in a VF without having to first size-down other
	 * VFs.
	 */
	return max(min(num_vf_msix / num_vfs, max_msix / 2), min_msix);
}

/**
 * mlx5_set_msix_vec_count - Set dynamically allocated MSI-X on the VF
 * @dev: PF to work on
 * @function_id: Internal PCI VF function IDd
 * @msix_vec_count: Number of MSI-X vectors to set
 */
int mlx5_set_msix_vec_count(struct mlx5_core_dev *dev, int function_id,
			    int msix_vec_count)
{
	int query_sz = MLX5_ST_SZ_BYTES(query_hca_cap_out);
	int set_sz = MLX5_ST_SZ_BYTES(set_hca_cap_in);
	void *hca_cap = NULL, *query_cap = NULL, *cap;
	int num_vf_msix, min_msix, max_msix;
	int ret;

	num_vf_msix = MLX5_CAP_GEN_MAX(dev, num_total_dynamic_vf_msix);
	if (!num_vf_msix)
		return 0;

	if (!MLX5_CAP_GEN(dev, vport_group_manager) || !mlx5_core_is_pf(dev))
		return -EOPNOTSUPP;

	min_msix = MLX5_CAP_GEN(dev, min_dynamic_vf_msix_table_size);
	max_msix = MLX5_CAP_GEN(dev, max_dynamic_vf_msix_table_size);

	if (msix_vec_count < min_msix)
		return -EINVAL;

	if (msix_vec_count > max_msix)
		return -EOVERFLOW;

	query_cap = kzalloc(query_sz, GFP_KERNEL);
	hca_cap = kzalloc(set_sz, GFP_KERNEL);
	if (!hca_cap || !query_cap) {
		ret = -ENOMEM;
		goto out;
	}

	ret = mlx5_vport_get_other_func_cap(dev, function_id, query_cap);
	if (ret)
		goto out;

	cap = MLX5_ADDR_OF(set_hca_cap_in, hca_cap, capability);
	memcpy(cap, MLX5_ADDR_OF(query_hca_cap_out, query_cap, capability),
	       MLX5_UN_SZ_BYTES(hca_cap_union));
	MLX5_SET(cmd_hca_cap, cap, dynamic_msix_table_size, msix_vec_count);

	MLX5_SET(set_hca_cap_in, hca_cap, opcode, MLX5_CMD_OP_SET_HCA_CAP);
	MLX5_SET(set_hca_cap_in, hca_cap, other_function, 1);
	MLX5_SET(set_hca_cap_in, hca_cap, function_id, function_id);

	MLX5_SET(set_hca_cap_in, hca_cap, op_mod,
		 MLX5_SET_HCA_CAP_OP_MOD_GENERAL_DEVICE << 1);
	ret = mlx5_cmd_exec_in(dev, set_hca_cap, hca_cap);
out:
	kfree(hca_cap);
	kfree(query_cap);
	return ret;
}

static void cpu_put(struct mlx5_irq_table *table, cpumask_var_t mask)
{
	int cpu;

	if (cpumask_empty(mask))
		return;

	cpu = cpumask_first(mask);
	atomic_dec(&table->cpus[cpu]);
}

static void cpu_get(struct mlx5_irq_table *table, cpumask_var_t affinity)
{
	int cpu;

	if (cpumask_empty(affinity))
		return;
	cpu = cpumask_first(affinity);
	atomic_inc(&table->cpus[cpu]);
}

static void irq_release(struct kref *kref)
{
	struct mlx5_irq *irq = container_of(kref, struct mlx5_irq, kref);
	struct mlx5_irq_pool *pool = irq->pool;

	cpu_put(mlx5_irq_table_get(irq->pool->dev), irq->mask);
	xa_erase(&pool->irqs, irq->index);
	/* free_irq requires that affinity and rmap will be cleared
	 * before calling it. This is why there is asymmetry with set_rmap
	 * which should be called after alloc_irq but before request_irq.
	 */
	irq_set_affinity_hint(irq->irqn, NULL);
	free_cpumask_var(irq->mask);
	free_irq(irq->irqn, &irq->nh);
	kfree(irq);
}

static void irq_put(struct mlx5_irq *irq)
{
	struct mlx5_irq_pool *pool = irq->pool;

	mutex_lock(&pool->lock);
	kref_put(&irq->kref, irq_release);
	mutex_unlock(&pool->lock);
}

static irqreturn_t irq_int_handler(int irq, void *nh)
{
	atomic_notifier_call_chain(nh, 0, NULL);
	return IRQ_HANDLED;
}

static void irq_sf_set_name(struct mlx5_irq_pool *pool, char *name, int vecidx)
{
	snprintf(name, MLX5_MAX_IRQ_NAME, "%s%d", pool->name, vecidx);
}

static void irq_set_name(char *name, int vecidx)
{
	if (vecidx == 0) {
		snprintf(name, MLX5_MAX_IRQ_NAME, "mlx5_async%d", vecidx);
		return;
	}

	snprintf(name, MLX5_MAX_IRQ_NAME, "mlx5_comp%d",
		 vecidx - MLX5_IRQ_VEC_COMP_BASE);
	return;
}

static void affinity_copy(struct mlx5_irq *irq, struct cpumask *affinity,
			  struct mlx5_irq_table *irq_table)
{
	if (affinity)
		cpumask_copy(irq->mask, affinity);
	else
		cpumask_set_cpu(mlx5_irq_table_cpu_pick_default(irq_table), irq->mask);
}

static struct mlx5_irq *irq_request(struct mlx5_irq_pool *pool, int i,
				    struct cpumask *affinity)
{
#ifndef HAVE_PCI_IRQ_API
	struct mlx5_priv *priv  = &pool->dev->priv;
	struct msix_entry *msix;
#endif
	struct mlx5_core_dev *dev = pool->dev;
	char name[MLX5_MAX_IRQ_NAME];
	struct mlx5_irq *irq;
	int err;

	irq = kzalloc(sizeof(*irq), GFP_KERNEL);
	if (!irq)
		return ERR_PTR(-ENOMEM);
#ifdef HAVE_PCI_IRQ_API
	irq->irqn = pci_irq_vector(dev->pdev, i);
#else
	msix = priv->msix_arr;
	irq->irqn = msix[i].vector;
#endif
	if (!pool->name[0])
		irq_set_name(name, i);
	else
		irq_sf_set_name(pool, name, i);
	ATOMIC_INIT_NOTIFIER_HEAD(&irq->nh);
	snprintf(irq->name, MLX5_MAX_IRQ_NAME,
		 "%s@pci:%s", name, pci_name(dev->pdev));
	err = request_irq(irq->irqn, irq_int_handler, 0, irq->name,
			  &irq->nh);
	if (err) {
		mlx5_core_err(dev, "Failed to request irq. err = %d\n", err);
		goto err_req_irq;
	}
	if (!zalloc_cpumask_var(&irq->mask, GFP_KERNEL)) {
		mlx5_core_warn(dev, "zalloc_cpumask_var failed\n");
		err = -ENOMEM;
		goto err_cpumask;
	}
	irq->pool = pool;
	kref_init(&irq->kref);
	irq->index = i;
	err = xa_err(xa_store(&pool->irqs, irq->index, irq, GFP_KERNEL));
	if (err) {
		mlx5_core_err(dev, "Failed to alloc xa entry for irq(%u). err = %d\n",
			      irq->index, err);
		goto err_xa;
	}
	affinity_copy(irq, affinity, mlx5_irq_table_get(dev));
	irq_set_affinity_hint(irq->irqn, irq->mask);
	cpu_get(mlx5_irq_table_get(dev), irq->mask);
	return irq;
err_xa:
	free_cpumask_var(irq->mask);
err_cpumask:
	free_irq(irq->irqn, &irq->nh);
err_req_irq:
	kfree(irq);
	return ERR_PTR(err);
}

static struct mlx5_irq *irq_create(struct mlx5_irq_pool *pool,
				   struct cpumask *affinity)
{
	struct mlx5_irq *irq;
	u32 irq_index;
	int err;

	err = xa_alloc(&pool->irqs, &irq_index, NULL, pool->xa_num_irqs,
		       GFP_KERNEL);
	if (err) {
		if (err == -EBUSY)
			err = -EUSERS;
		return ERR_PTR(err);
	}
	irq = irq_request(pool, irq_index, affinity);
	if (IS_ERR(irq))
		return irq;
	return irq;
}

int mlx5_irq_attach_nb(struct mlx5_irq *irq, struct notifier_block *nb)
{
	int err;

	err = kref_get_unless_zero(&irq->kref);
	if (WARN_ON_ONCE(!err))
		/* Something very bad happens here, we are enabling EQ
		 * on non-existing IRQ.
		 */
		return -ENOENT;
	err = atomic_notifier_chain_register(&irq->nh, nb);
	if (err)
		irq_put(irq);
	return err;
}

int mlx5_irq_detach_nb(struct mlx5_irq *irq, struct notifier_block *nb)
{
	irq_put(irq);
	return atomic_notifier_chain_unregister(&irq->nh, nb);
}

struct cpumask *mlx5_irq_get_affinity_mask(struct mlx5_irq *irq)
{
	return irq->mask;
}

/* irq_pool API */

static int irq_pool_size_get(struct mlx5_irq_pool *pool)
{
	return pool->xa_num_irqs.max - pool->xa_num_irqs.min + 1;
}

static struct mlx5_irq *irq_pool_find_least_loaded(struct mlx5_irq_pool *pool,
						   struct cpumask *affinity)
{
	int start = pool->xa_num_irqs.min;
	int end = pool->xa_num_irqs.max;
	struct mlx5_irq *irq = NULL;
	struct mlx5_irq *iter;
	unsigned long index;

	lockdep_assert_held(&pool->lock);
	xa_for_each_range(&pool->irqs, index, iter, start, end) {
		if (!cpumask_equal(iter->mask, affinity))
			continue;
		if (kref_read(&iter->kref) < pool->min_threshold)
			return iter;
		if (!irq || kref_read(&iter->kref) <
		    kref_read(&irq->kref))
			irq = iter;
	}
	return irq;
}

static struct mlx5_irq *irq_pool_request_affinity(struct mlx5_irq_pool *pool,
						  struct cpumask *affinity)
{
	struct mlx5_irq *least_loaded_irq, *new_irq;

	mutex_lock(&pool->lock);
	least_loaded_irq = irq_pool_find_least_loaded(pool, affinity);
	if (least_loaded_irq &&
	    kref_read(&least_loaded_irq->kref) < pool->min_threshold) {
		kref_get(&least_loaded_irq->kref);
		mutex_unlock(&pool->lock);
		return least_loaded_irq;
	}
	new_irq = irq_create(pool, affinity);
	if (IS_ERR(new_irq)) {
		if (!least_loaded_irq) {
			mlx5_core_err(pool->dev, "Didn't find IRQ for cpu = %u\n",
				      cpumask_first(affinity));
			least_loaded_irq = new_irq;
			goto unlock;
		}
		/* We failed to create a new IRQ for the requested affinity,
		 * sharing existing IRQ.
		 */
		kref_get(&least_loaded_irq->kref);
	} else {
		least_loaded_irq = new_irq;
	}
	if (kref_read(&least_loaded_irq->kref) > pool->max_threshold)
		mlx5_core_dbg(pool->dev, "IRQ %u overloaded, pool_name: %s, %u EQs on this irq\n",
			      least_loaded_irq->irqn, pool->name,
			      kref_read(&least_loaded_irq->kref) / MLX5_EQ_REFS_PER_IRQ);
unlock:
	mutex_unlock(&pool->lock);
	return least_loaded_irq;
}

static struct mlx5_irq *
irq_pool_request_vector(struct mlx5_irq_pool *pool, int vecidx,
			struct cpumask *affinity)
{
	struct mlx5_irq *irq;

	mutex_lock(&pool->lock);
	irq = xa_load(&pool->irqs, vecidx);
	if (irq) {
		kref_get(&irq->kref);
		goto unlock;
	}
	irq = irq_request(pool, vecidx, affinity);
unlock:
	mutex_unlock(&pool->lock);
	return irq;
}

static struct mlx5_irq_pool *find_sf_irq_pool(struct mlx5_irq_table *irq_table,
					      int i, struct cpumask *affinity)
{
	if (cpumask_empty(affinity) && i == MLX5_IRQ_EQ_CTRL)
		return irq_table->sf_ctrl_pool;
	return irq_table->sf_comp_pool;
}

/**
 * mlx5_irq_release - release an IRQ back to the system.
 * @irq - irq to be released.
 */
void mlx5_irq_release(struct mlx5_irq *irq)
{
	synchronize_irq(irq->irqn);
	irq_put(irq);
}

/**
 * mlx5_irq_request - request an IRQ for mlx5 device.
 * @dev - mlx5 device that requesting the IRQ.
 * @vecidx - vector index of the IRQ. This argument is ignore if affinity is
 * provided.
 * @affinity - cpumask requested for this IRQ.
 */
struct mlx5_irq *mlx5_irq_request(struct mlx5_core_dev *dev, u16 *vecidx,
				  struct cpumask *affinity)
{
	struct mlx5_irq_table *irq_table = mlx5_irq_table_get(dev);
	struct mlx5_irq_pool *pool;
	struct mlx5_irq *irq;
	int i = *vecidx;

	if (mlx5_core_is_sf(dev)) {
		pool = find_sf_irq_pool(irq_table, i, affinity);
		if (!pool) {
			pool = irq_table->pf_pool;
			irq = irq_pool_request_vector(pool, i, affinity);
		} else if (cpumask_empty(affinity) && !strcmp(pool->name, "mlx5_sf_comp")) {
			/* In case an SF user request IRQ with vecidx */
			irq = irq_pool_request_vector(pool, i, NULL);
		} else {
			irq = irq_pool_request_affinity(pool, affinity);
		}
	} else {
		pool = irq_table->pf_pool;
		irq = irq_pool_request_vector(pool, i, affinity);
	}
	if (IS_ERR(irq))
		return irq;
	if (!cpumask_empty(irq->mask)) {
		mlx5_core_dbg(dev, "irq %u mapped to cpu %d, %u EQs on this irq\n",
			      irq->irqn, cpumask_first(irq->mask),
			      kref_read(&irq->kref) / MLX5_EQ_REFS_PER_IRQ);
	}
	*vecidx = irq->index;
	return irq;
}

void mlx5_irq_rename(struct mlx5_core_dev *dev, struct mlx5_irq *irq,
		     const char *name)
{
	char *dst_name = irq->name;

	if (!name) {
		char default_name[MLX5_MAX_IRQ_NAME];

		irq_set_name(default_name, irq->index);
		snprintf(dst_name, MLX5_MAX_IRQ_NAME,
			 "%s@pci:%s", default_name, pci_name(dev->pdev));
	} else {
		snprintf(dst_name, MLX5_MAX_IRQ_NAME, "%s-%d", name,
			 irq->index - MLX5_IRQ_VEC_COMP_BASE);
	}
}

static struct mlx5_irq_pool *
irq_pool_alloc(struct mlx5_core_dev *dev, int start, int size, char *name,
	       u32 min_threshold, u32 max_threshold)
{
	struct mlx5_irq_pool *pool = kvzalloc(sizeof(*pool), GFP_KERNEL);

	if (!pool)
		return ERR_PTR(-ENOMEM);
	pool->dev = dev;
	xa_init_flags(&pool->irqs, XA_FLAGS_ALLOC);
	pool->xa_num_irqs.min = start;
	pool->xa_num_irqs.max = start + size - 1;
	if (name)
		snprintf(pool->name, MLX5_MAX_IRQ_NAME - MLX5_MAX_IRQ_IDX_CHARS,
			 name);
	pool->min_threshold = min_threshold * MLX5_EQ_REFS_PER_IRQ;
	pool->max_threshold = max_threshold * MLX5_EQ_REFS_PER_IRQ;
	mutex_init(&pool->lock);
	return pool;
}

static void irq_pool_free(struct mlx5_irq_pool *pool)
{
	struct mlx5_irq *irq;
	unsigned long index;

	xa_for_each(&pool->irqs, index, irq)
		irq_release(&irq->kref);
	xa_destroy(&pool->irqs);
	kvfree(pool);
}

static int irq_pools_init(struct mlx5_core_dev *dev, int sf_vec, int pf_vec)
{
	struct mlx5_irq_table *table = dev->priv.irq_table;
	int num_sf_ctrl_by_msix;
	int num_sf_ctrl_by_sfs;
	int num_sf_ctrl;
	int err;

	/* init pf_pool */
	table->pf_pool = irq_pool_alloc(dev, 0, pf_vec, NULL,
					MLX5_EQ_SHARE_IRQ_MIN_COMP,
					MLX5_EQ_SHARE_IRQ_MAX_COMP);
	if (IS_ERR(table->pf_pool))
		return PTR_ERR(table->pf_pool);
	if (!mlx5_sf_max_functions(dev))
		return 0;
	if (sf_vec < MLX5_IRQ_VEC_COMP_BASE_SF) {
		mlx5_core_warn(dev, "Not enough IRQs for SFs, SFs may run at lower performance\n");
		return 0;
	}

	/* init sf_ctrl_pool */
	num_sf_ctrl_by_msix = DIV_ROUND_UP(sf_vec, MLX5_COMP_EQS_PER_SF);
	num_sf_ctrl_by_sfs = DIV_ROUND_UP(mlx5_sf_max_functions(dev),
					  MLX5_SFS_PER_CTRL_IRQ);
	num_sf_ctrl = min_t(int, num_sf_ctrl_by_msix, num_sf_ctrl_by_sfs);
	num_sf_ctrl = min_t(int, MLX5_IRQ_CTRL_SF_MAX, num_sf_ctrl);
	table->sf_ctrl_pool = irq_pool_alloc(dev, pf_vec, num_sf_ctrl,
					     "mlx5_sf_ctrl",
					     MLX5_EQ_SHARE_IRQ_MIN_CTRL,
					     MLX5_EQ_SHARE_IRQ_MAX_CTRL);
	if (IS_ERR(table->sf_ctrl_pool)) {
		err = PTR_ERR(table->sf_ctrl_pool);
		goto err_pf;
	}
	/* init sf_comp_pool */
	table->sf_comp_pool = irq_pool_alloc(dev, pf_vec + num_sf_ctrl,
					     sf_vec - num_sf_ctrl, "mlx5_sf_comp",
					     MLX5_EQ_SHARE_IRQ_MIN_COMP,
					     MLX5_EQ_SHARE_IRQ_MAX_COMP);
	if (IS_ERR(table->sf_comp_pool)) {
		err = PTR_ERR(table->sf_comp_pool);
		goto err_sf_ctrl;
	}
	return 0;
err_sf_ctrl:
	irq_pool_free(table->sf_ctrl_pool);
err_pf:
	irq_pool_free(table->pf_pool);
	return err;
}

static void irq_pools_destroy(struct mlx5_irq_table *table)
{
	irq_pool_free(table->pf_pool);
	if (table->sf_ctrl_pool) {
		irq_pool_free(table->sf_ctrl_pool);
		irq_pool_free(table->sf_comp_pool);
	}
}

/* irq_table API */

int mlx5_irq_table_init(struct mlx5_core_dev *dev)
{
	struct mlx5_irq_table *irq_table;

	if (mlx5_core_is_sf(dev))
		return 0;

	irq_table = kvzalloc(sizeof(*irq_table), GFP_KERNEL);
	if (!irq_table)
		return -ENOMEM;

	dev->priv.irq_table = irq_table;
	return 0;
}

void mlx5_irq_table_cleanup(struct mlx5_core_dev *dev)
{
	if (mlx5_core_is_sf(dev))
		return;

	kvfree(dev->priv.irq_table);
}

int mlx5_irq_table_get_num_comp(struct mlx5_irq_table *table)
{
	return irq_pool_size_get(table->pf_pool) - MLX5_IRQ_VEC_COMP_BASE;
}

int mlx5_irq_table_create(struct mlx5_core_dev *dev)
{
	struct mlx5_irq_table *table = dev->priv.irq_table;
	int max_num_eq = MLX5_CAP_GEN(dev, max_num_eqs);
	int num_eqs;
	int max_comp_eqs;
	int total_vec;
	int pf_vec;
	int err;
#ifndef HAVE_PCI_IRQ_API
	struct mlx5_priv* priv = &dev->priv;
	int i;
#endif

	if (mlx5_core_is_sf(dev))
		return 0;

	if (max_num_eq) {
		num_eqs = max_num_eq;
	} else {
		num_eqs = 1 << MLX5_CAP_GEN(dev, log_max_eq);
		num_eqs -= MLX5_FW_RESERVED_EQS;
		if (num_eqs <= 0)
			return -ENOMEM;
	}

	max_comp_eqs = num_eqs - MLX5_MAX_ASYNC_EQS;
	pf_vec = MLX5_CAP_GEN(dev, num_ports) * num_online_cpus() +
		 MLX5_IRQ_VEC_COMP_BASE;
	pf_vec = min_t(int, pf_vec, num_eqs);
	if (pf_vec <= MLX5_IRQ_VEC_COMP_BASE)
		return -ENOMEM;

	total_vec = pf_vec;
	if (mlx5_sf_max_functions(dev))
		total_vec += MLX5_IRQ_CTRL_SF_MAX +
			MLX5_COMP_EQS_PER_SF * mlx5_sf_max_functions(dev);

#ifndef HAVE_PCI_IRQ_API
	priv->msix_arr = kcalloc(total_vec, sizeof(*priv->msix_arr), GFP_KERNEL);
	if (!priv->msix_arr)
		return -ENOMEM;

	for (i = 0; i < total_vec; i++)
		priv->msix_arr[i].entry = i;
#endif

#ifdef HAVE_PCI_IRQ_API
	total_vec = pci_alloc_irq_vectors(dev->pdev, MLX5_IRQ_VEC_COMP_BASE + 1,
					  total_vec, PCI_IRQ_MSIX);
	if (total_vec < 0) {
		err = total_vec;
		goto err_free_irq;
	}
#else /* HAVE_PCI_IRQ_API */
#ifdef HAVE_PCI_ENABLE_MSIX_RANGE
	total_vec = pci_enable_msix_range(dev->pdev, priv->msix_arr,
			MLX5_IRQ_VEC_COMP_BASE + 1, total_vec);
	if (total_vec < 0) {
		err = total_vec;
		goto err_free_irq;
	}

#else /* HAVE_PCI_ENABLE_MSIX_RANGE */
retry:
	err = pci_enable_msix(dev->pdev, priv->msix_arr, total_vec);
	if (err < 0) {
		goto err_free_irq;
	} else if (err > 2) {
		total_vec = err;
		goto retry;
	} else if (err) {
		mlx5_core_err(dev, "Can't enable the minimum required num of MSIX, %d\n", err);
		goto err_free_irq;
	}
	mlx5_core_dbg(dev, "received %d MSI vectors out of %d requested\n", err, total_vec);
#endif /* HAVE_PCI_ENABLE_MSIX_RANGE */
#endif /* HAVE_PCI_IRQ_API */

	table->cpus = kvcalloc(nr_cpu_ids, sizeof(atomic_t), GFP_KERNEL);
	if (!table->cpus) {
		err = -ENOMEM;
		goto err_cpus;
	}
	pf_vec = min(pf_vec, total_vec);

	err = irq_pools_init(dev, total_vec - pf_vec, pf_vec);
	if (err)
		goto err_init_pools;

	return 0;
err_init_pools:
	kvfree(table->cpus);
err_cpus:
#ifdef HAVE_PCI_IRQ_API
	pci_free_irq_vectors(dev->pdev);
#else
	pci_disable_msix(dev->pdev);
#endif
err_free_irq:
#ifndef HAVE_PCI_IRQ_API
	kfree(priv->msix_arr);
#endif
	return err;
}

void mlx5_irq_table_destroy(struct mlx5_core_dev *dev)
{
	struct mlx5_irq_table *table = dev->priv.irq_table;
	unsigned int cpu;

	if (mlx5_core_is_sf(dev))
		return;

	/* There are cases where IRQs still will be in used when we reaching
	 * to here. Hence, making sure all the irqs are realeased.
	 */
	irq_pools_destroy(table);
#ifdef HAVE_PCI_IRQ_API
	pci_free_irq_vectors(dev->pdev);
#else
	pci_disable_msix(dev->pdev);
	kfree(dev->priv.msix_arr);
#endif
	for_each_online_cpu(cpu)
		WARN_ON(atomic_read(&table->cpus[cpu]));
	kvfree(table->cpus);
}

unsigned int mlx5_irq_table_cpu_pick_default(struct mlx5_irq_table *table)
{
	int sf_comp_vec = mlx5_irq_table_get_sfs_comp_vec(table);
	int best_cpu = 0;
	int i = 0;
	int cpu;

	for_each_online_cpu(cpu) {
		if (atomic_read(&table->cpus[best_cpu]) >
		    atomic_read(&table->cpus[cpu]))
			best_cpu = cpu;
		i++;
		if (i >= sf_comp_vec)
			break;
	}
	return best_cpu;
}

bool mlx5_have_dedicated_irqs(struct mlx5_core_dev *dev)
{
	struct mlx5_irq_table *table = mlx5_irq_table_get(dev);

	if (mlx5_core_is_sf(dev) && !table->sf_comp_pool)
		return false;
	return true;
}

int mlx5_irq_table_get_sfs_comp_vec(struct mlx5_irq_table *table)
{
	if (table->sf_comp_pool)
		return irq_pool_size_get(table->sf_comp_pool);
	else
		return mlx5_irq_table_get_num_comp(table);
}

struct mlx5_irq_table *mlx5_irq_table_get(struct mlx5_core_dev *dev)
{
#ifdef CONFIG_MLX5_SF
	if (mlx5_core_is_sf(dev))
		return dev->priv.parent_mdev->priv.irq_table;
#endif
	return dev->priv.irq_table;
}
