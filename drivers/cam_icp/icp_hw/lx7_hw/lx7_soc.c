// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#include <linux/interrupt.h>
#include <linux/of.h>

#include "cam_debug_util.h"
#include "cam_soc_util.h"
#include "lx7_soc.h"

static int __ubwc_config_get(struct device_node *np, char *name, uint32_t *cfg)
{
	int nconfig;
	int i;

	nconfig = of_property_count_u32_elems(np, name);
	if (nconfig < 0 || nconfig > UBWC_CONFIG_MAX) {
		CAM_ERR(CAM_ICP, "invalid number of UBWC configs[=%d]",
			nconfig);
		return -EINVAL;
	}

	for (i = 0; i < nconfig; i++) {
		int rc;

		rc = of_property_read_u32_index(np, name, i, &cfg[i]);
		if (rc) {
			CAM_ERR(CAM_ICP,
				"node %pOF has no valid %s prop at index=%d",
				np, name, i);
			return rc;
		}
	}

	return 0;
}

static int cam_lx7_ubwc_config_get(struct lx7_soc_info *lx7_soc_info,
				struct device_node *np)
{
	int rc;

	rc = __ubwc_config_get(np, "ubwc-ipe-fetch-cfg",
			lx7_soc_info->ubwc_cfg.ipe_fetch);
	if (rc)
		return rc;

	rc = __ubwc_config_get(np, "ubwc-ipe-write-cfg",
			lx7_soc_info->ubwc_cfg.ipe_write);
	if (rc)
		return rc;

	rc = __ubwc_config_get(np, "ubwc-bps-fetch-cfg",
			lx7_soc_info->ubwc_cfg.bps_fetch);
	if (rc)
		return rc;

	rc = __ubwc_config_get(np, "ubwc-bps-write-cfg",
			lx7_soc_info->ubwc_cfg.bps_write);
	if (rc)
		return rc;

	return 0;
}

static int cam_lx7_dt_properties_get(struct cam_hw_soc_info *soc_info)
{
	int rc;

	rc = cam_soc_util_get_dt_properties(soc_info);
	if (rc) {
		CAM_ERR(CAM_ICP, "failed to get DT properties rc=%d", rc);
		return rc;
	}

	rc = cam_lx7_ubwc_config_get(soc_info->soc_private,
				soc_info->pdev->dev.of_node);
	if (rc) {
		CAM_ERR(CAM_ICP, "failed to get UBWC config props rc=%d", rc);
		return rc;
	}

	return 0;
}

int cam_lx7_soc_resources_init(struct cam_hw_soc_info *soc_info,
			irq_handler_t handler, void *data)
{
	int rc;

	rc = cam_lx7_dt_properties_get(soc_info);
	if (rc)
		return rc;

	rc = cam_soc_util_request_platform_resource(soc_info, handler, data);
	if (rc) {
		CAM_ERR(CAM_ICP,
			"request for soc platform resource failed rc=%d", rc);
		return rc;
	}

	return 0;
}

int cam_lx7_soc_resources_deinit(struct cam_hw_soc_info *soc_info)
{
	int rc;

	rc = cam_soc_util_release_platform_resource(soc_info);
	if (rc)
		CAM_ERR(CAM_ICP,
			"release of soc platform resource failed rc=%d", rc);

	return rc;
}

int cam_lx7_soc_resources_enable(struct cam_hw_soc_info *soc_info)
{
	int rc = 0;

	rc = cam_soc_util_enable_platform_resource(soc_info, true,
						CAM_SVS_VOTE, true);
	if (rc)
		CAM_ERR(CAM_ICP, "failed to enable soc resources rc=%d", rc);

	return rc;
}

int cam_lx7_soc_resources_disable(struct cam_hw_soc_info *soc_info)
{
	int rc = 0;

	rc = cam_soc_util_disable_platform_resource(soc_info, true, true);
	if (rc)
		CAM_ERR(CAM_ICP, "failed to disable soc resources rc=%d", rc);

	return rc;
}
