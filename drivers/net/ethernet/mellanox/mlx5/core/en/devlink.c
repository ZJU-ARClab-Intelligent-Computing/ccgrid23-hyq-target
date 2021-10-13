// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2020, Mellanox Technologies inc.  All rights reserved. */

#include "en_rep.h"
#include "en/devlink.h"
#include "eswitch.h"

#if defined(HAVE_DEVLINK_PORT_ATRRS_SET_GET_2_PARAMS) || defined(HAVE_DEVLINK_PORT_ATRRS_SET_GET_7_PARAMS)
static void
mlx5e_devlink_get_port_parent_id(struct mlx5_core_dev *dev, struct netdev_phys_item_id *ppid)
{
	u64 parent_id;

	parent_id = mlx5_query_nic_system_image_guid(dev);
	ppid->id_len = sizeof(parent_id);
	memcpy(ppid->id, &parent_id, sizeof(parent_id));
}
#endif

#ifdef HAVE_DEVLINK_PORT_ATRRS_SET_GET_SUPPORT
int mlx5e_devlink_port_register(struct mlx5e_priv *priv)
{
	struct devlink *devlink = priv_to_devlink(priv->mdev);
	struct devlink_port *dl_port;
	unsigned int dl_port_index;
#ifdef HAVE_DEVLINK_PORT_ATRRS_SET_GET_2_PARAMS
	struct devlink_port_attrs attrs = {};
	struct netdev_phys_item_id ppid = {};

	if (mlx5_core_is_pf(priv->mdev)) {
		attrs.flavour = DEVLINK_PORT_FLAVOUR_PHYSICAL;
		attrs.phys.port_number = PCI_FUNC(priv->mdev->pdev->devfn);
		if (MLX5_ESWITCH_MANAGER(priv->mdev)) {
			mlx5e_devlink_get_port_parent_id(priv->mdev, &ppid);
			memcpy(attrs.switch_id.id, ppid.id, ppid.id_len);
			attrs.switch_id.id_len = ppid.id_len;
		}
		dl_port_index = mlx5_esw_vport_to_devlink_port_index(priv->mdev,
								     MLX5_VPORT_UPLINK);
	} else {
		attrs.flavour = DEVLINK_PORT_FLAVOUR_VIRTUAL;
		dl_port_index = mlx5_esw_vport_to_devlink_port_index(priv->mdev, 0);
	}

	dl_port = mlx5e_devlink_get_dl_port(priv);
	memset(dl_port, 0, sizeof(*dl_port));
	devlink_port_attrs_set(dl_port, &attrs);
#else
	dl_port = mlx5e_devlink_get_dl_port(priv);
	memset(dl_port, 0, sizeof(*dl_port));
	if (mlx5_core_is_pf(priv->mdev)) {
#ifdef HAVE_DEVLINK_PORT_ATRRS_SET_GET_7_PARAMS
		struct netdev_phys_item_id ppid = {};

		if (MLX5_ESWITCH_MANAGER(priv->mdev))
			mlx5e_devlink_get_port_parent_id(priv->mdev, &ppid);
#endif
		dl_port_index = mlx5_esw_vport_to_devlink_port_index(priv->mdev,
								     MLX5_VPORT_UPLINK);
		devlink_port_attrs_set(dl_port,
				DEVLINK_PORT_FLAVOUR_PHYSICAL,
				PCI_FUNC(priv->mdev->pdev->devfn),
				false, 0
#ifdef HAVE_DEVLINK_PORT_ATRRS_SET_GET_7_PARAMS
				,&ppid.id[0], ppid.id_len
#endif
		);
	} else {
		dl_port_index = mlx5_esw_vport_to_devlink_port_index(priv->mdev, 0);
		devlink_port_attrs_set(dl_port,
				DEVLINK_PORT_FLAVOUR_VIRTUAL,
				0, false , 0
#ifdef HAVE_DEVLINK_PORT_ATRRS_SET_GET_7_PARAMS
				,NULL, 0
#endif
		);
	}
#endif
	return devlink_port_register(devlink, dl_port, dl_port_index);
}

void mlx5e_devlink_port_type_eth_set(struct mlx5e_priv *priv)
{
	struct devlink_port *dl_port = mlx5e_devlink_get_dl_port(priv);

	devlink_port_type_eth_set(dl_port, priv->netdev);
}

void mlx5e_devlink_port_unregister(struct mlx5e_priv *priv)
{
	struct devlink_port *dl_port = mlx5e_devlink_get_dl_port(priv);

	devlink_port_unregister(dl_port);
}

struct devlink_port *mlx5e_get_devlink_port(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	if (!netif_device_present(dev))
		return NULL;

	return mlx5e_devlink_get_dl_port(priv);
}
#endif
