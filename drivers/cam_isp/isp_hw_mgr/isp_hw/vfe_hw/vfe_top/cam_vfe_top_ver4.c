// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2019-2021, The Linux Foundation. All rights reserved.
 */

#include <linux/slab.h>
#include "cam_io_util.h"
#include "cam_cdm_util.h"
#include "cam_vfe_hw_intf.h"
#include "cam_vfe_top.h"
#include "cam_vfe_top_ver4.h"
#include "cam_debug_util.h"
#include "cam_vfe_soc.h"
#include "cam_trace.h"
#include "cam_isp_hw_mgr_intf.h"
#include "cam_irq_controller.h"
#include "cam_tasklet_util.h"
#include "cam_cdm_intf_api.h"

#define CAM_VFE_HW_RESET_HW_AND_REG_VAL       0x00000001
#define CAM_VFE_HW_RESET_HW_VAL               0x00010000
#define CAM_VFE_LITE_HW_RESET_AND_REG_VAL     0x00000002
#define CAM_VFE_LITE_HW_RESET_HW_VAL          0x00000001
#define CAM_CDM_WAIT_COMP_EVENT_BIT           0x2

#define CAM_VFE_CAMIF_IRQ_SOF_DEBUG_CNT_MAX 2


struct cam_vfe_mux_ver4_data {
	void __iomem                                *mem_base;
	struct cam_hw_soc_info                      *soc_info;
	struct cam_hw_intf                          *hw_intf;
	struct cam_vfe_top_ver4_reg_offset_common   *common_reg;
	struct cam_vfe_top_common_cfg                cam_common_cfg;
	struct cam_vfe_ver4_path_reg_data           *reg_data;
	struct cam_vfe_top_ver4_module_desc         *module_desc;

	cam_hw_mgr_event_cb_func             event_cb;
	void                                *priv;
	int                                  irq_err_handle;
	int                                  irq_handle;
	int                                  sof_irq_handle;
	void                                *vfe_irq_controller;
	struct cam_vfe_top_irq_evt_payload   evt_payload[CAM_VFE_CAMIF_EVT_MAX];
	struct list_head                     free_payload_list;
	spinlock_t                           spin_lock;

	enum cam_isp_hw_sync_mode          sync_mode;
	uint32_t                           dsp_mode;
	uint32_t                           pix_pattern;
	uint32_t                           first_pixel;
	uint32_t                           first_line;
	uint32_t                           last_pixel;
	uint32_t                           last_line;
	uint32_t                           hbi_value;
	uint32_t                           vbi_value;
	bool                               enable_sof_irq_debug;
	uint32_t                           irq_debug_cnt;
	uint32_t                           camif_debug;
	uint32_t                           horizontal_bin;
	uint32_t                           qcfa_bin;
	uint32_t                           dual_hw_idx;
	uint32_t                           is_dual;
	bool                               is_fe_enabled;
	bool                               is_offline;
	bool                               is_lite;
	bool                               is_pixel_path;
	bool                               sfe_binned_epoch_cfg;

	struct timespec64                     sof_ts;
	struct timespec64                     epoch_ts;
	struct timespec64                     eof_ts;
	struct timespec64                     error_ts;
};

struct cam_vfe_top_ver4_common_data {
	struct cam_hw_soc_info                     *soc_info;
	struct cam_hw_intf                         *hw_intf;
	struct cam_vfe_top_ver4_reg_offset_common  *common_reg;
};

struct cam_vfe_top_ver4_priv {
	struct cam_vfe_top_ver4_common_data common_data;
	unsigned long                       hw_clk_rate;
	unsigned long                       req_clk_rate[
						CAM_VFE_TOP_MUX_MAX];
	struct cam_vfe_top_priv_common      top_common;
};

static int cam_vfe_top_ver4_mux_get_base(struct cam_vfe_top_ver4_priv *top_priv,
	void *cmd_args, uint32_t arg_size)
{
	uint32_t                          size = 0;
	uint32_t                          mem_base = 0;
	struct cam_isp_hw_get_cmd_update *cdm_args  = cmd_args;
	struct cam_cdm_utils_ops         *cdm_util_ops = NULL;

	if (arg_size != sizeof(struct cam_isp_hw_get_cmd_update)) {
		CAM_ERR(CAM_ISP, "Error, Invalid cmd size");
		return -EINVAL;
	}

	if (!cdm_args || !cdm_args->res || !top_priv ||
		!top_priv->common_data.soc_info) {
		CAM_ERR(CAM_ISP, "Error, Invalid args");
		return -EINVAL;
	}

	cdm_util_ops =
		(struct cam_cdm_utils_ops *)cdm_args->res->cdm_ops;

	if (!cdm_util_ops) {
		CAM_ERR(CAM_ISP, "Invalid CDM ops");
		return -EINVAL;
	}

	size = cdm_util_ops->cdm_required_size_changebase();
	/* since cdm returns dwords, we need to convert it into bytes */
	if ((size * 4) > cdm_args->cmd.size) {
		CAM_ERR(CAM_ISP, "buf size:%d is not sufficient, expected: %d",
			cdm_args->cmd.size, size);
		return -EINVAL;
	}

	mem_base = CAM_SOC_GET_REG_MAP_CAM_BASE(
		top_priv->common_data.soc_info, VFE_CORE_BASE_IDX);
	if (cdm_args->cdm_id == CAM_CDM_RT)
		mem_base -= CAM_SOC_GET_REG_MAP_CAM_BASE(
			top_priv->common_data.soc_info, RT_BASE_IDX);

	CAM_DBG(CAM_ISP, "core %d mem_base 0x%x, cdm_id: %u",
		top_priv->common_data.soc_info->index, mem_base,
		cdm_args->cdm_id);

	cdm_util_ops->cdm_write_changebase(
		cdm_args->cmd.cmd_buf_addr, mem_base);
	cdm_args->cmd.used_bytes = (size * 4);

	return 0;
}

static int cam_vfe_top_ver4_set_hw_clk_rate(
	struct cam_vfe_top_ver4_priv *top_priv)
{
	struct cam_hw_soc_info        *soc_info = NULL;
	struct cam_vfe_soc_private    *soc_private = NULL;
	struct cam_ahb_vote            ahb_vote;
	int                            i, rc = 0, clk_lvl = -1;
	unsigned long                  max_clk_rate = 0;

	soc_info = top_priv->common_data.soc_info;
	soc_private =
		(struct cam_vfe_soc_private *)soc_info->soc_private;

	for (i = 0; i < top_priv->top_common.num_mux; i++) {
		if (top_priv->req_clk_rate[i] > max_clk_rate)
			max_clk_rate = top_priv->req_clk_rate[i];
	}
	if (max_clk_rate == top_priv->hw_clk_rate)
		return 0;

	CAM_DBG(CAM_PERF, "VFE: Clock name=%s idx=%d clk=%llu",
		soc_info->clk_name[soc_info->src_clk_idx],
		soc_info->src_clk_idx, max_clk_rate);

	rc = cam_soc_util_set_src_clk_rate(soc_info, max_clk_rate);

	if (!rc) {
		top_priv->hw_clk_rate = max_clk_rate;
		rc = cam_soc_util_get_clk_level(soc_info, max_clk_rate,
			soc_info->src_clk_idx, &clk_lvl);
		if (rc) {
			CAM_WARN(CAM_ISP,
				"Failed to get clk level for %s with clk_rate %llu src_idx %d rc %d",
				soc_info->dev_name, max_clk_rate,
				soc_info->src_clk_idx, rc);
			rc = 0;
			goto end;
		}
		ahb_vote.type = CAM_VOTE_ABSOLUTE;
		ahb_vote.vote.level = clk_lvl;
		cam_cpas_update_ahb_vote(soc_private->cpas_handle, &ahb_vote);
	} else {
		CAM_ERR(CAM_PERF, "Set Clock rate failed, rc=%d", rc);
	}

end:
	return rc;
}

static int cam_vfe_top_fs_update(
	struct cam_vfe_top_ver4_priv *top_priv,
	void *cmd_args, uint32_t arg_size)
{
	struct cam_vfe_fe_update_args *cmd_update = cmd_args;

	if (cmd_update->node_res->process_cmd)
		return cmd_update->node_res->process_cmd(cmd_update->node_res,
			CAM_ISP_HW_CMD_FE_UPDATE_IN_RD, cmd_args, arg_size);

	return 0;
}

static int cam_vfe_top_ver4_clock_update(
	struct cam_vfe_top_ver4_priv *top_priv,
	void *cmd_args, uint32_t arg_size)
{
	struct cam_vfe_clock_update_args     *clk_update = NULL;
	struct cam_isp_resource_node         *res = NULL;
	struct cam_hw_info                   *hw_info = NULL;
	int                                   i, rc = 0;

	clk_update =
		(struct cam_vfe_clock_update_args *)cmd_args;
	res = clk_update->node_res;

	if (!res || !res->hw_intf->hw_priv) {
		CAM_ERR(CAM_PERF, "Invalid input res %pK", res);
		return -EINVAL;
	}

	hw_info = res->hw_intf->hw_priv;

	if (res->res_type != CAM_ISP_RESOURCE_VFE_IN ||
		res->res_id >= CAM_ISP_HW_VFE_IN_MAX) {
		CAM_ERR(CAM_PERF, "VFE:%d Invalid res_type:%d res id%d",
			res->hw_intf->hw_idx, res->res_type,
			res->res_id);
		return -EINVAL;
	}

	for (i = 0; i < top_priv->top_common.num_mux; i++) {
		if (top_priv->top_common.mux_rsrc[i].res_id == res->res_id) {
			top_priv->req_clk_rate[i] = clk_update->clk_rate;
			break;
		}
	}

	if (hw_info->hw_state != CAM_HW_STATE_POWER_UP) {
		CAM_DBG(CAM_PERF,
			"VFE:%d Not ready to set clocks yet :%d",
			res->hw_intf->hw_idx,
			hw_info->hw_state);
	} else
		rc = cam_vfe_top_ver4_set_hw_clk_rate(top_priv);

	return rc;
}

static int cam_vfe_top_ver4_dump_info(
	struct cam_vfe_top_ver4_priv *top_priv, uint32_t cmd_type)
{
	struct cam_hw_soc_info *soc_info = top_priv->common_data.soc_info;

	if (!soc_info) {
		CAM_ERR(CAM_ISP, "Null soc_info");
		return -EINVAL;
	}

	switch (cmd_type) {
	case CAM_ISP_HW_DUMP_HW_SRC_CLK_RATE:
		CAM_INFO_RATE_LIMIT(CAM_ISP, "VFE%d src_clk_rate:%luHz",
			soc_info->index, soc_info->applied_src_clk_rate);
		break;
	default:
		CAM_ERR(CAM_ISP, "cmd_type: %u not supported", cmd_type);
		break;
	}

	return 0;
}

static int cam_vfe_core_config_control(
	struct cam_vfe_top_ver4_priv *top_priv,
	 void *cmd_args, uint32_t arg_size)
{
	struct cam_vfe_core_config_args *vfe_core_cfg =
		(struct cam_vfe_core_config_args *)cmd_args;
	struct cam_isp_resource_node *rsrc_node = vfe_core_cfg->node_res;
	struct cam_vfe_mux_ver4_data *vfe_priv;

	vfe_priv =
		(struct cam_vfe_mux_ver4_data *)rsrc_node->res_priv;
	vfe_priv->cam_common_cfg.vid_ds16_r2pd =
		vfe_core_cfg->core_config.vid_ds16_r2pd;
	vfe_priv->cam_common_cfg.vid_ds4_r2pd =
		vfe_core_cfg->core_config.vid_ds4_r2pd;
	vfe_priv->cam_common_cfg.disp_ds16_r2pd =
		vfe_core_cfg->core_config.disp_ds16_r2pd;
	vfe_priv->cam_common_cfg.disp_ds4_r2pd =
		vfe_core_cfg->core_config.disp_ds4_r2pd;
	vfe_priv->cam_common_cfg.dsp_streaming_tap_point =
		vfe_core_cfg->core_config.dsp_streaming_tap_point;
	vfe_priv->cam_common_cfg.ihist_src_sel =
		vfe_core_cfg->core_config.ihist_src_sel;

	return 0;
}

static int cam_vfe_top_ver4_mux_get_reg_update(
	struct cam_vfe_top_ver4_priv *top_priv,
	void *cmd_args, uint32_t arg_size)
{
	CAM_ERR(CAM_ISP, "Invalid request, Add RUP in CSID");
	return -EINVAL;
}

static int cam_vfe_top_ver4_get_data(
	struct cam_vfe_top_ver4_priv *top_priv,
	void *cmd_args, uint32_t arg_size)
{
	struct cam_isp_resource_node  *res = cmd_args;

	if (res->process_cmd)
		return res->process_cmd(res,
			CAM_ISP_HW_CMD_CAMIF_DATA, cmd_args, arg_size);

	return -EINVAL;
}

int cam_vfe_top_ver4_get_hw_caps(void *device_priv,
	void *get_hw_cap_args, uint32_t arg_size)
{
	return -EPERM;
}

int cam_vfe_top_ver4_init_hw(void *device_priv,
	void *init_hw_args, uint32_t arg_size)
{
	struct cam_vfe_top_ver4_priv   *top_priv = device_priv;
	struct cam_vfe_top_ver4_common_data common_data = top_priv->common_data;

	top_priv->hw_clk_rate = 0;

	/**
	 * Auto clock gating is enabled by default, but no harm
	 * in setting the value we expect.
	 */
	CAM_INFO(CAM_ISP, "Enabling clock gating at IFE top");

	cam_soc_util_w_mb(common_data.soc_info, VFE_CORE_BASE_IDX,
		common_data.common_reg->core_cgc_ovd_0, 0x0);

	cam_soc_util_w_mb(common_data.soc_info, VFE_CORE_BASE_IDX,
		common_data.common_reg->core_cgc_ovd_1, 0x0);

	cam_soc_util_w_mb(common_data.soc_info, VFE_CORE_BASE_IDX,
		common_data.common_reg->ahb_cgc_ovd, 0x0);

	cam_soc_util_w_mb(common_data.soc_info, VFE_CORE_BASE_IDX,
		common_data.common_reg->noc_cgc_ovd, 0x0);

	return 0;
}

int cam_vfe_top_ver4_reset(void *device_priv,
	void *reset_core_args, uint32_t arg_size)
{
	CAM_DBG(CAM_ISP, "Reset not supported");
	return 0;
}

int cam_vfe_top_acquire_resource(
	struct cam_isp_resource_node  *vfe_full_res,
	void                          *acquire_param)
{
	struct cam_vfe_mux_ver4_data      *res_data;
	struct cam_vfe_acquire_args       *acquire_data;
	int                                    rc = 0;

	res_data  = (struct cam_vfe_mux_ver4_data *)
		vfe_full_res->res_priv;
	acquire_data = (struct cam_vfe_acquire_args *)acquire_param;

	if (rc) {
		CAM_ERR(CAM_ISP, "Validate pix pattern failed, rc = %d", rc);
		return rc;
	}

	res_data->sync_mode      = acquire_data->vfe_in.sync_mode;
	res_data->event_cb       = acquire_data->event_cb;
	res_data->priv           = acquire_data->priv;

	if (!res_data->is_pixel_path)
		goto config_done;

	res_data->pix_pattern    = acquire_data->vfe_in.in_port->test_pattern;
	res_data->dsp_mode       = acquire_data->vfe_in.in_port->dsp_mode;
	res_data->first_pixel    = acquire_data->vfe_in.in_port->left_start;
	res_data->last_pixel     = acquire_data->vfe_in.in_port->left_stop;
	res_data->first_line     = acquire_data->vfe_in.in_port->line_start;
	res_data->last_line      = acquire_data->vfe_in.in_port->line_stop;
	res_data->is_fe_enabled  = acquire_data->vfe_in.is_fe_enabled;
	res_data->is_offline     = acquire_data->vfe_in.is_offline;
	res_data->is_dual        = acquire_data->vfe_in.is_dual;
	res_data->qcfa_bin       = acquire_data->vfe_in.in_port->qcfa_bin;
	res_data->horizontal_bin =
		acquire_data->vfe_in.in_port->horizontal_bin;
	res_data->vbi_value      = 0;
	res_data->hbi_value      = 0;
	res_data->sfe_binned_epoch_cfg = (bool)
		acquire_data->vfe_in.in_port->sfe_binned_epoch_cfg;

	if (res_data->is_dual)
		res_data->dual_hw_idx = acquire_data->vfe_in.dual_hw_idx;

config_done:
	CAM_DBG(CAM_ISP,
		"VFE:%d pix_pattern:%d dsp_mode=%d is_dual:%d dual_hw_idx:%d",
		vfe_full_res->hw_intf->hw_idx,
		res_data->pix_pattern, res_data->dsp_mode,
		res_data->is_dual, res_data->dual_hw_idx);

	return rc;
}

int cam_vfe_top_ver4_reserve(void *device_priv,
	void *reserve_args, uint32_t arg_size)
{
	struct cam_vfe_top_ver4_priv            *top_priv;
	struct cam_vfe_acquire_args             *args;
	struct cam_vfe_hw_vfe_in_acquire_args   *acquire_args;
	uint32_t i;
	int rc = -EINVAL;

	if (!device_priv || !reserve_args) {
		CAM_ERR(CAM_ISP, "Error, Invalid input arguments");
		return -EINVAL;
	}

	top_priv = (struct cam_vfe_top_ver4_priv   *)device_priv;
	args = (struct cam_vfe_acquire_args *)reserve_args;
	acquire_args = &args->vfe_in;

	CAM_DBG(CAM_ISP, "res id %d", acquire_args->res_id);


	for (i = 0; i < top_priv->top_common.num_mux; i++) {
		if (top_priv->top_common.mux_rsrc[i].res_id ==
			acquire_args->res_id &&
			top_priv->top_common.mux_rsrc[i].res_state ==
			CAM_ISP_RESOURCE_STATE_AVAILABLE) {

			if (acquire_args->res_id == CAM_ISP_HW_VFE_IN_CAMIF) {
				rc = cam_vfe_top_acquire_resource(
					&top_priv->top_common.mux_rsrc[i],
					args);
				if (rc)
					break;
			}

			if (acquire_args->res_id >= CAM_ISP_HW_VFE_IN_RDI0 &&
				acquire_args->res_id < CAM_ISP_HW_VFE_IN_MAX) {
				rc = cam_vfe_top_acquire_resource(
					&top_priv->top_common.mux_rsrc[i],
					args);
				if (rc)
					break;
			}

			if (acquire_args->res_id == CAM_ISP_HW_VFE_IN_RD) {
				rc = cam_vfe_fe_ver1_acquire_resource(
					&top_priv->top_common.mux_rsrc[i],
					args);
				if (rc)
					break;
			}

			top_priv->top_common.mux_rsrc[i].cdm_ops =
				acquire_args->cdm_ops;
			top_priv->top_common.mux_rsrc[i].tasklet_info =
				args->tasklet;
			top_priv->top_common.mux_rsrc[i].res_state =
				CAM_ISP_RESOURCE_STATE_RESERVED;
			acquire_args->rsrc_node =
				&top_priv->top_common.mux_rsrc[i];

			rc = 0;
			break;
		}
	}

	return rc;

}

int cam_vfe_top_ver4_release(void *device_priv,
	void *release_args, uint32_t arg_size)
{
	struct cam_vfe_top_ver4_priv            *top_priv;
	struct cam_isp_resource_node            *mux_res;

	if (!device_priv || !release_args) {
		CAM_ERR(CAM_ISP, "Error, Invalid input arguments");
		return -EINVAL;
	}

	top_priv = (struct cam_vfe_top_ver4_priv   *)device_priv;
	mux_res = (struct cam_isp_resource_node *)release_args;

	CAM_DBG(CAM_ISP, "Resource in state %d", mux_res->res_state);
	if (mux_res->res_state < CAM_ISP_RESOURCE_STATE_RESERVED) {
		CAM_ERR(CAM_ISP, "Error, Resource in Invalid res_state :%d",
			mux_res->res_state);
		return -EINVAL;
	}
	mux_res->res_state = CAM_ISP_RESOURCE_STATE_AVAILABLE;

	return 0;
}

static void cam_vfe_top_ver4_print_debug_reg_status(
	struct cam_vfe_mux_ver4_data            *mux_data,
	uint32_t                                *irq_status)
{
	uint32_t val0, val1, val2, val3;

	val0 = cam_io_r(mux_data->mem_base +
		mux_data->common_reg->top_debug_0);
	val1 = cam_io_r(mux_data->mem_base +
		mux_data->common_reg->top_debug_1);
	val2 = cam_io_r(mux_data->mem_base +
		mux_data->common_reg->top_debug_2);
	val3 = cam_io_r(mux_data->mem_base +
		mux_data->common_reg->top_debug_3);

	CAM_INFO(CAM_ISP,
		"status_0: 0x%x status_1: 0x%x status_2: 0x%x status_3: 0x%x",
		val0, val1, val2, val3);

	val0 = cam_io_r(mux_data->mem_base +
		mux_data->common_reg->top_debug_4);
	val1 = cam_io_r(mux_data->mem_base +
		mux_data->common_reg->top_debug_5);
	val2 = cam_io_r(mux_data->mem_base +
		mux_data->common_reg->top_debug_6);
	val3 = cam_io_r(mux_data->mem_base +
		mux_data->common_reg->top_debug_7);

	CAM_INFO(CAM_ISP,
		"status_4: 0x%x status_5: 0x%x status_6: 0x%x status_7: 0x%x",
		val0, val1, val2, val3);

	val0 = cam_io_r(mux_data->mem_base +
		mux_data->common_reg->top_debug_8);
	val1 = cam_io_r(mux_data->mem_base +
		mux_data->common_reg->top_debug_9);
	val2 = cam_io_r(mux_data->mem_base +
		mux_data->common_reg->top_debug_10);
	val3 = cam_io_r(mux_data->mem_base +
		mux_data->common_reg->top_debug_11);
	CAM_INFO(CAM_ISP,
		"status_8: 0x%x status_9: 0x%x status_10: 0x%x status_11: 0x%x",
		val0, val1, val2, val3);

	val0 = cam_io_r(mux_data->mem_base +
		mux_data->common_reg->top_debug_12);
	val1 = cam_io_r(mux_data->mem_base +
		mux_data->common_reg->top_debug_13);
	CAM_INFO(CAM_ISP, "status_12: 0x%x status_13: 0x%x",
		val0, val1);

	if (irq_status[CAM_IFE_IRQ_CAMIF_REG_STATUS0] &&
		mux_data->reg_data->pp_violation_mask) {

		val0 =  cam_io_r(mux_data->mem_base +
				mux_data->common_reg->violation_status),

		CAM_ERR(CAM_ISP, "VFE[%u] PP Violation status 0x%x",
		     mux_data->hw_intf->hw_idx, val0);

		if (mux_data->module_desc)
			CAM_ERR(CAM_ISP, "VFE[%u] PP Violation Module[%u] %s",
				mux_data->hw_intf->hw_idx,
				mux_data->module_desc[val0].id,
				mux_data->module_desc[val0].desc);
	}

	CAM_ERR(CAM_ISP, "VFE[%u] Bus overflow status 0x%x",
		mux_data->hw_intf->hw_idx,
		cam_io_r(mux_data->mem_base +
			mux_data->common_reg->bus_overflow_status));

	CAM_ERR(CAM_ISP, "VFE[%u] Bus  Violation status 0x%x",
		mux_data->hw_intf->hw_idx,
		cam_io_r(mux_data->mem_base +
			mux_data->common_reg->bus_violation_status));
}

int cam_vfe_top_ver4_start(void *device_priv,
	void *start_args, uint32_t arg_size)
{
	struct cam_vfe_top_ver4_priv            *top_priv;
	struct cam_isp_resource_node            *mux_res;
	struct cam_hw_info                      *hw_info = NULL;
	struct cam_hw_soc_info                  *soc_info = NULL;
	struct cam_vfe_soc_private              *soc_private = NULL;
	int rc = 0;

	if (!device_priv || !start_args) {
		CAM_ERR(CAM_ISP, "Error, Invalid input arguments");
		return -EINVAL;
	}

	top_priv = (struct cam_vfe_top_ver4_priv *)device_priv;
	soc_info = top_priv->common_data.soc_info;
	soc_private = soc_info->soc_private;
	if (!soc_private) {
		CAM_ERR(CAM_ISP, "Error soc_private NULL");
		return -EINVAL;
	}

	mux_res = (struct cam_isp_resource_node *)start_args;
	hw_info = (struct cam_hw_info  *)mux_res->hw_intf->hw_priv;

	if (hw_info->hw_state == CAM_HW_STATE_POWER_UP) {
		rc = cam_vfe_top_ver4_set_hw_clk_rate(top_priv);
		if (rc) {
			CAM_ERR(CAM_ISP,
				"set_hw_clk_rate failed, rc=%d", rc);
			return rc;
		}

		rc = cam_vfe_top_set_axi_bw_vote(soc_private,
			&top_priv->top_common, true);
		if (rc) {
			CAM_ERR(CAM_ISP,
				"set_axi_bw_vote failed, rc=%d", rc);
			return rc;
		}

		if (mux_res->start) {
			rc = mux_res->start(mux_res);
		} else {
			CAM_ERR(CAM_ISP,
				"Invalid res id:%d", mux_res->res_id);
			rc = -EINVAL;
		}
	} else {
		CAM_ERR(CAM_ISP, "VFE HW not powered up");
		rc = -EPERM;
	}

	return rc;
}

int cam_vfe_top_ver4_stop(void *device_priv,
	void *stop_args, uint32_t arg_size)
{
	struct cam_vfe_top_ver4_priv            *top_priv;
	struct cam_isp_resource_node            *mux_res;
	struct cam_hw_info                      *hw_info = NULL;
	int i, rc = 0;

	if (!device_priv || !stop_args) {
		CAM_ERR(CAM_ISP, "Error, Invalid input arguments");
		return -EINVAL;
	}

	top_priv = (struct cam_vfe_top_ver4_priv   *)device_priv;
	mux_res = (struct cam_isp_resource_node *)stop_args;
	hw_info = (struct cam_hw_info  *)mux_res->hw_intf->hw_priv;

	if (mux_res->res_id < CAM_ISP_HW_VFE_IN_MAX) {
		rc = mux_res->stop(mux_res);
	} else {
		CAM_ERR(CAM_ISP, "Invalid res id:%d", mux_res->res_id);
		return -EINVAL;
	}

	if (!rc) {
		for (i = 0; i < top_priv->top_common.num_mux; i++) {
			if (top_priv->top_common.mux_rsrc[i].res_id ==
				mux_res->res_id) {
				top_priv->req_clk_rate[i] = 0;
				memset(&top_priv->top_common.req_axi_vote[i],
					0, sizeof(struct cam_axi_vote));
				top_priv->top_common.axi_vote_control[i] =
					CAM_VFE_BW_CONTROL_EXCLUDE;
				break;
			}
		}
	}

	return rc;
}

int cam_vfe_top_ver4_read(void *device_priv,
	void *read_args, uint32_t arg_size)
{
	return -EPERM;
}

int cam_vfe_top_ver4_write(void *device_priv,
	void *write_args, uint32_t arg_size)
{
	return -EPERM;
}

int cam_vfe_top_ver4_process_cmd(void *device_priv, uint32_t cmd_type,
	void *cmd_args, uint32_t arg_size)
{
	int rc = 0;
	struct cam_vfe_top_ver4_priv            *top_priv;
	struct cam_hw_soc_info                  *soc_info = NULL;
	struct cam_vfe_soc_private              *soc_private = NULL;

	if (!device_priv || !cmd_args) {
		CAM_ERR(CAM_ISP, "Error, Invalid arguments");
		return -EINVAL;
	}

	top_priv = (struct cam_vfe_top_ver4_priv *)device_priv;
	soc_info = top_priv->common_data.soc_info;
	soc_private = soc_info->soc_private;
	if (!soc_private) {
		CAM_ERR(CAM_ISP, "Error soc_private NULL");
		return -EINVAL;
	}

	switch (cmd_type) {
	case CAM_ISP_HW_CMD_GET_CHANGE_BASE:
		rc = cam_vfe_top_ver4_mux_get_base(top_priv,
			cmd_args, arg_size);
		break;
	case CAM_ISP_HW_CMD_GET_REG_UPDATE:
		rc = cam_vfe_top_ver4_mux_get_reg_update(top_priv, cmd_args,
			arg_size);
		break;
	case CAM_ISP_HW_CMD_CAMIF_DATA:
		rc = cam_vfe_top_ver4_get_data(top_priv, cmd_args,
			arg_size);
		break;
	case CAM_ISP_HW_CMD_CLOCK_UPDATE:
		rc = cam_vfe_top_ver4_clock_update(top_priv, cmd_args,
			arg_size);
		break;
	case CAM_ISP_HW_DUMP_HW_SRC_CLK_RATE:
		rc = cam_vfe_top_ver4_dump_info(top_priv, cmd_type);
		break;
	case CAM_ISP_HW_CMD_FE_UPDATE_IN_RD:
		rc = cam_vfe_top_fs_update(top_priv, cmd_args,
			arg_size);
		break;
	case CAM_ISP_HW_CMD_BW_UPDATE:
		rc = cam_vfe_top_bw_update(soc_private, &top_priv->top_common,
			cmd_args, arg_size);
		break;
	case CAM_ISP_HW_CMD_BW_UPDATE_V2:
		rc = cam_vfe_top_bw_update_v2(soc_private,
			&top_priv->top_common, cmd_args, arg_size);
		break;
	case CAM_ISP_HW_CMD_BW_CONTROL:
		rc = cam_vfe_top_bw_control(soc_private, &top_priv->top_common,
			cmd_args, arg_size);
		break;
	case CAM_ISP_HW_CMD_CORE_CONFIG:
		rc = cam_vfe_core_config_control(top_priv, cmd_args, arg_size);
		break;
	default:
		rc = -EINVAL;
		CAM_ERR(CAM_ISP, "Error, Invalid cmd:%d", cmd_type);
		break;
	}

	return rc;
}

static int cam_vfe_get_evt_payload(
	struct cam_vfe_mux_ver4_data           *vfe_priv,
	struct cam_vfe_top_irq_evt_payload    **evt_payload)
{
	int rc = 0;

	spin_lock(&vfe_priv->spin_lock);
	if (list_empty(&vfe_priv->free_payload_list)) {
		CAM_ERR_RATE_LIMIT(CAM_ISP, "No free VFE event payload");
		rc = -ENODEV;
		goto done;
	}

	*evt_payload = list_first_entry(&vfe_priv->free_payload_list,
		struct cam_vfe_top_irq_evt_payload, list);
	list_del_init(&(*evt_payload)->list);
done:
	spin_unlock(&vfe_priv->spin_lock);
	return rc;
}

static int cam_vfe_top_put_evt_payload(
	struct cam_vfe_mux_ver4_data           *vfe_priv,
	struct cam_vfe_top_irq_evt_payload    **evt_payload)
{
	unsigned long flags;

	if (!vfe_priv) {
		CAM_ERR(CAM_ISP, "Invalid param core_info NULL");
		return -EINVAL;
	}
	if (*evt_payload == NULL) {
		CAM_ERR(CAM_ISP, "No payload to put");
		return -EINVAL;
	}

	spin_lock_irqsave(&vfe_priv->spin_lock, flags);
	list_add_tail(&(*evt_payload)->list, &vfe_priv->free_payload_list);
	*evt_payload = NULL;
	spin_unlock_irqrestore(&vfe_priv->spin_lock, flags);

	CAM_DBG(CAM_ISP, "Done");
	return 0;
}

static int cam_vfe_handle_irq_top_half(uint32_t evt_id,
	struct cam_irq_th_payload *th_payload)
{
	int32_t                                rc;
	int                                    i;
	struct cam_isp_resource_node          *vfe_res;
	struct cam_vfe_mux_ver4_data          *vfe_priv;
	struct cam_vfe_top_irq_evt_payload    *evt_payload;

	vfe_res = th_payload->handler_priv;
	vfe_priv = vfe_res->res_priv;

	CAM_DBG(CAM_ISP,
		"VFE:%d IRQ status_0: 0x%X status_1: 0x%X",
		vfe_res->hw_intf->hw_idx, th_payload->evt_status_arr[0],
		th_payload->evt_status_arr[1]);

	rc  = cam_vfe_get_evt_payload(vfe_priv, &evt_payload);
	if (rc) {
		CAM_INFO_RATE_LIMIT(CAM_ISP,
		"VFE:%d IRQ status_0: 0x%X status_1: 0x%X",
		vfe_res->hw_intf->hw_idx, th_payload->evt_status_arr[0],
		th_payload->evt_status_arr[1]);
		return rc;
	}

	cam_isp_hw_get_timestamp(&evt_payload->ts);
	evt_payload->reg_val = 0;

	for (i = 0; i < th_payload->num_registers; i++)
		evt_payload->irq_reg_val[i] = th_payload->evt_status_arr[i];

	th_payload->evt_payload_priv = evt_payload;

	if (th_payload->evt_status_arr[CAM_IFE_IRQ_CAMIF_REG_STATUS1]
			& vfe_priv->reg_data->sof_irq_mask) {
		trace_cam_log_event("SOF", "TOP_HALF",
		th_payload->evt_status_arr[CAM_IFE_IRQ_CAMIF_REG_STATUS1],
		vfe_res->hw_intf->hw_idx);
	}

	if (th_payload->evt_status_arr[CAM_IFE_IRQ_CAMIF_REG_STATUS1]
			& vfe_priv->reg_data->epoch0_irq_mask) {
		trace_cam_log_event("EPOCH0", "TOP_HALF",
		th_payload->evt_status_arr[CAM_IFE_IRQ_CAMIF_REG_STATUS1],
		vfe_res->hw_intf->hw_idx);
	}

	if (th_payload->evt_status_arr[CAM_IFE_IRQ_CAMIF_REG_STATUS1]
			& vfe_priv->reg_data->eof_irq_mask) {
		trace_cam_log_event("EOF", "TOP_HALF",
		th_payload->evt_status_arr[CAM_IFE_IRQ_CAMIF_REG_STATUS1],
		vfe_res->hw_intf->hw_idx);
	}

	CAM_DBG(CAM_ISP, "Exit");
	return rc;
}


static int cam_vfe_handle_irq_bottom_half(void *handler_priv,
	void *evt_payload_priv)
{
	int ret = CAM_VFE_IRQ_STATUS_ERR;
	struct cam_isp_resource_node *vfe_res;
	struct cam_vfe_mux_ver4_data *vfe_priv;
	struct cam_vfe_top_irq_evt_payload *payload;
	struct cam_isp_hw_event_info evt_info;
	uint32_t irq_status[CAM_IFE_IRQ_REGISTERS_MAX] = {0};
	struct timespec64 ts;
	int i = 0;

	if (!handler_priv || !evt_payload_priv) {
		CAM_ERR(CAM_ISP,
			"Invalid params handle_priv:%pK, evt_payload_priv:%pK",
			handler_priv, evt_payload_priv);
		return ret;
	}

	vfe_res = handler_priv;
	vfe_priv = vfe_res->res_priv;
	payload = evt_payload_priv;

	for (i = 0; i < CAM_IFE_IRQ_REGISTERS_MAX; i++)
		irq_status[i] = payload->irq_reg_val[i];

	evt_info.hw_idx   = vfe_res->hw_intf->hw_idx;
	evt_info.res_id   = vfe_res->res_id;
	evt_info.res_type = vfe_res->res_type;
	evt_info.reg_val = 0;

	if (irq_status[CAM_IFE_IRQ_CAMIF_REG_STATUS1]
		& vfe_priv->reg_data->sof_irq_mask) {
		if ((vfe_priv->enable_sof_irq_debug) &&
			(vfe_priv->irq_debug_cnt <=
			CAM_VFE_CAMIF_IRQ_SOF_DEBUG_CNT_MAX)) {
			CAM_INFO_RATE_LIMIT(CAM_ISP, "VFE:%d Received SOF",
				evt_info.hw_idx);

			vfe_priv->irq_debug_cnt++;
			if (vfe_priv->irq_debug_cnt ==
				CAM_VFE_CAMIF_IRQ_SOF_DEBUG_CNT_MAX) {
				vfe_priv->enable_sof_irq_debug =
					false;
				vfe_priv->irq_debug_cnt = 0;
			}
		} else {
			CAM_DBG(CAM_ISP, "VFE:%d Received SOF",
				evt_info.hw_idx);
			vfe_priv->sof_ts.tv_sec =
				payload->ts.mono_time.tv_sec;
			vfe_priv->sof_ts.tv_nsec =
				payload->ts.mono_time.tv_nsec;
		}

		if (vfe_priv->event_cb)
			vfe_priv->event_cb(vfe_priv->priv,
				CAM_ISP_HW_EVENT_SOF, (void *)&evt_info);
		ret = CAM_VFE_IRQ_STATUS_SUCCESS;
	}

	if (irq_status[CAM_IFE_IRQ_CAMIF_REG_STATUS1]
		& vfe_priv->reg_data->epoch0_irq_mask) {
		CAM_DBG(CAM_ISP, "VFE:%d Received EPOCH", evt_info.hw_idx);
		evt_info.reg_val = payload->reg_val;
		vfe_priv->epoch_ts.tv_sec =
			payload->ts.mono_time.tv_sec;
		vfe_priv->epoch_ts.tv_nsec =
			payload->ts.mono_time.tv_nsec;

		if (vfe_priv->event_cb)
			vfe_priv->event_cb(vfe_priv->priv,
				CAM_ISP_HW_EVENT_EPOCH, (void *)&evt_info);
		ret = CAM_VFE_IRQ_STATUS_SUCCESS;
	}

	if (irq_status[CAM_IFE_IRQ_CAMIF_REG_STATUS1]
		& vfe_priv->reg_data->eof_irq_mask) {
		CAM_DBG(CAM_ISP, "VFE:%d Received EOF", evt_info.hw_idx);
		vfe_priv->eof_ts.tv_sec =
			payload->ts.mono_time.tv_sec;
		vfe_priv->eof_ts.tv_nsec =
			payload->ts.mono_time.tv_nsec;

		if (vfe_priv->event_cb)
			vfe_priv->event_cb(vfe_priv->priv,
				CAM_ISP_HW_EVENT_EOF, (void *)&evt_info);

		ret = CAM_VFE_IRQ_STATUS_SUCCESS;
	}

	if (irq_status[CAM_IFE_IRQ_CAMIF_REG_STATUS0]
		& vfe_priv->reg_data->error_irq_mask) {
		CAM_ERR(CAM_ISP, "VFE:%d Overflow", evt_info.hw_idx);

		ktime_get_boottime_ts64(&ts);
		CAM_INFO(CAM_ISP,
			"current monotonic time stamp seconds %lld:%lld",
			ts.tv_sec, ts.tv_nsec);

		if (vfe_priv->event_cb)
			vfe_priv->event_cb(vfe_priv->priv,
				CAM_ISP_HW_EVENT_ERROR, (void *)&evt_info);
		cam_vfe_top_ver4_print_debug_reg_status(vfe_priv,
			irq_status);

		ret = CAM_VFE_IRQ_STATUS_ERR;
	}

	if (vfe_priv->camif_debug & CAMIF_DEBUG_ENABLE_SENSOR_DIAG_STATUS) {
		CAM_DBG(CAM_ISP, "VFE:%d VFE_DIAG_SENSOR_STATUS: 0x%X",
			evt_info.hw_idx, vfe_priv->mem_base,
			cam_io_r(vfe_priv->mem_base +
			vfe_priv->common_reg->diag_sensor_status_0));
	}

	cam_vfe_top_put_evt_payload(vfe_priv, &payload);

	CAM_DBG(CAM_ISP, "returning status = %d", ret);
	return ret;
}

static int cam_vfe_ver4_err_irq_top_half(
	uint32_t                               evt_id,
	struct cam_irq_th_payload             *th_payload)
{
	int32_t                                rc = 0;
	int                                    i;
	struct cam_isp_resource_node          *vfe_res;
	struct cam_vfe_mux_ver4_data          *vfe_priv;
	struct cam_vfe_top_irq_evt_payload    *evt_payload;
	bool                                   error_flag = false;

	vfe_res = th_payload->handler_priv;
	vfe_priv = vfe_res->res_priv;
	/*
	 *  need to handle overflow condition here, otherwise irq storm
	 *  will block everything
	 */
	if ((th_payload->evt_status_arr[0] &
		vfe_priv->reg_data->error_irq_mask)) {
		CAM_ERR(CAM_ISP,
			"VFE:%d Err IRQ status_0: 0x%X",
			vfe_res->hw_intf->hw_idx,
			th_payload->evt_status_arr[0]);
		CAM_ERR(CAM_ISP, "Stopping further IRQ processing from VFE:%d",
			vfe_res->hw_intf->hw_idx);
		cam_irq_controller_disable_irq(vfe_priv->vfe_irq_controller,
			vfe_priv->irq_err_handle);
		cam_irq_controller_clear_and_mask(evt_id,
			vfe_priv->vfe_irq_controller);
		error_flag = true;
	}

	rc  = cam_vfe_get_evt_payload(vfe_priv, &evt_payload);
	if (rc)
		return rc;

	cam_isp_hw_get_timestamp(&evt_payload->ts);
	if (error_flag) {
		vfe_priv->error_ts.tv_sec =
			evt_payload->ts.mono_time.tv_sec;
		vfe_priv->error_ts.tv_nsec =
			evt_payload->ts.mono_time.tv_nsec;
	}

	for (i = 0; i < th_payload->num_registers; i++)
		evt_payload->irq_reg_val[i] = th_payload->evt_status_arr[i];

	th_payload->evt_payload_priv = evt_payload;

	return rc;
}

static int cam_vfe_resource_start(
	struct cam_isp_resource_node *vfe_res)
{
	struct cam_vfe_mux_ver4_data   *rsrc_data;
	uint32_t                        val = 0;
	int                             rc = 0;
	uint32_t                        err_irq_mask[CAM_IFE_IRQ_REGISTERS_MAX];
	uint32_t                        irq_mask[CAM_IFE_IRQ_REGISTERS_MAX];

	if (!vfe_res) {
		CAM_ERR(CAM_ISP, "Error, Invalid input arguments");
		return -EINVAL;
	}

	if (vfe_res->res_state != CAM_ISP_RESOURCE_STATE_RESERVED) {
		CAM_ERR(CAM_ISP, "Error, Invalid camif res res_state:%d",
			vfe_res->res_state);
		return -EINVAL;
	}

	memset(err_irq_mask, 0, sizeof(err_irq_mask));
	memset(irq_mask, 0, sizeof(irq_mask));

	rsrc_data = (struct cam_vfe_mux_ver4_data *)vfe_res->res_priv;

	/* config debug status registers */
	cam_io_w_mb(rsrc_data->reg_data->top_debug_cfg_en, rsrc_data->mem_base +
		rsrc_data->common_reg->top_debug_cfg);

	if (rsrc_data->is_lite || !rsrc_data->is_pixel_path)
		goto skip_core_cfg;

	val = cam_io_r_mb(rsrc_data->mem_base +
		rsrc_data->common_reg->core_cfg_0);

	if ((rsrc_data->dsp_mode >= CAM_ISP_DSP_MODE_ONE_WAY) &&
		(rsrc_data->dsp_mode <= CAM_ISP_DSP_MODE_ROUND)) {
		/* DSP mode reg val is CAM_ISP_DSP_MODE - 1 */
		val |= (((rsrc_data->dsp_mode - 1) & 0x1) <<
			CAM_SHIFT_TOP_CORE_VER_4_CFG_DSP_MODE);
		val |= (0x1 << CAM_SHIFT_TOP_CORE_VER_4_CFG_DSP_EN);
	}

	val |= (~rsrc_data->cam_common_cfg.vid_ds16_r2pd & 0x1) <<
		CAM_SHIFT_TOP_CORE_VER_4_CFG_VID_DS16_R2PD;
	val |= (~rsrc_data->cam_common_cfg.vid_ds4_r2pd & 0x1) <<
		CAM_SHIFT_TOP_CORE_VER_4_CFG_VID_DS4_R2PD;
	val |= (~rsrc_data->cam_common_cfg.disp_ds16_r2pd & 0x1) <<
		CAM_SHIFT_TOP_CORE_VER_4_CFG_DISP_DS16_R2PD;
	val |= (~rsrc_data->cam_common_cfg.disp_ds4_r2pd & 0x1) <<
		CAM_SHIFT_TOP_CORE_VER_4_CFG_DISP_DS4_R2PD;
	val |= (rsrc_data->cam_common_cfg.dsp_streaming_tap_point & 0x3) <<
		CAM_SHIFT_TOP_CORE_VER_4_CFG_DSP_STREAMING;
	val |= (rsrc_data->cam_common_cfg.ihist_src_sel & 0x1) <<
		CAM_SHIFT_TOP_CORE_VER_4_CFG_STATS_IHIST;

	CAM_DBG(CAM_ISP, "VFE:%d TOP core_cfg: 0x%X",
		vfe_res->hw_intf->hw_idx, val);

	cam_io_w_mb(val, rsrc_data->mem_base +
		rsrc_data->common_reg->core_cfg_0);

	/* pixel fmt */
	val = cam_io_r_mb(rsrc_data->mem_base +
		rsrc_data->common_reg->core_cfg_1);

	/* get pixel fmt from in_port, after uapi changes are finalized */
	cam_io_w_mb(val, rsrc_data->mem_base +
		rsrc_data->common_reg->core_cfg_1);

	val = ((rsrc_data->last_line + rsrc_data->vbi_value) -
						rsrc_data->first_line) / 4;
	if (val > rsrc_data->last_line)
		val = rsrc_data->last_line;

	/* Epoch line cfg will still be configured at midpoint of the frame width.
	 * We use '/4' instead of '/2' because it is multipixel path.
	 */
	if (rsrc_data->horizontal_bin || rsrc_data->qcfa_bin ||
		rsrc_data->sfe_binned_epoch_cfg)
		val >>= 1;

	cam_io_w_mb(val, rsrc_data->mem_base +
				rsrc_data->common_reg->epoch_height_cfg);
	CAM_DBG(CAM_ISP, "epoch_line_cfg: 0x%X", val);

skip_core_cfg:
	vfe_res->res_state = CAM_ISP_RESOURCE_STATE_STREAMING;

	/* disable sof irq debug flag */
	rsrc_data->enable_sof_irq_debug = false;
	rsrc_data->irq_debug_cnt = 0;

	if (rsrc_data->camif_debug &
		CAMIF_DEBUG_ENABLE_SENSOR_DIAG_STATUS) {
		val = cam_io_r_mb(rsrc_data->mem_base +
			rsrc_data->common_reg->diag_config);
		val |= rsrc_data->reg_data->enable_diagnostic_hw;
		cam_io_w_mb(val, rsrc_data->mem_base +
			rsrc_data->common_reg->diag_config);
	}

	/* Skip subscribing to timing irqs in these scenarios:
	 *     1. Resource is dual IFE slave
	 *     2. Resource is not primary RDI
	 */
	if (((rsrc_data->sync_mode == CAM_ISP_HW_SYNC_SLAVE) && rsrc_data->is_dual) ||
		(!rsrc_data->is_pixel_path && !vfe_res->rdi_only_ctx))
		goto subscribe_err;

	irq_mask[CAM_IFE_IRQ_CAMIF_REG_STATUS1] =
		rsrc_data->reg_data->epoch0_irq_mask | rsrc_data->reg_data->eof_irq_mask;

	if (!rsrc_data->irq_handle) {
		rsrc_data->irq_handle = cam_irq_controller_subscribe_irq(
			rsrc_data->vfe_irq_controller,
			CAM_IRQ_PRIORITY_3,
			irq_mask,
			vfe_res,
			vfe_res->top_half_handler,
			vfe_res->bottom_half_handler,
			vfe_res->tasklet_info,
			&tasklet_bh_api);

		if (rsrc_data->irq_handle < 1) {
			CAM_ERR(CAM_ISP, "IRQ handle subscribe failure");
			rc = -ENOMEM;
			rsrc_data->irq_handle = 0;
		}
	}

	irq_mask[CAM_IFE_IRQ_CAMIF_REG_STATUS1] =
		rsrc_data->reg_data->sof_irq_mask;

	if (!rsrc_data->sof_irq_handle) {
		rsrc_data->sof_irq_handle = cam_irq_controller_subscribe_irq(
			rsrc_data->vfe_irq_controller,
			CAM_IRQ_PRIORITY_1,
			irq_mask,
			vfe_res,
			vfe_res->top_half_handler,
			vfe_res->bottom_half_handler,
			vfe_res->tasklet_info,
			&tasklet_bh_api);

		if (rsrc_data->sof_irq_handle < 1) {
			CAM_ERR(CAM_ISP, "SOF IRQ handle subscribe failure");
			rc = -ENOMEM;
			rsrc_data->sof_irq_handle = 0;
		}
	}

subscribe_err:
	err_irq_mask[CAM_IFE_IRQ_CAMIF_REG_STATUS0] = rsrc_data->reg_data->error_irq_mask;

	if (!rsrc_data->irq_err_handle) {
		rsrc_data->irq_err_handle = cam_irq_controller_subscribe_irq(
			rsrc_data->vfe_irq_controller,
			CAM_IRQ_PRIORITY_0,
			err_irq_mask,
			vfe_res,
			cam_vfe_ver4_err_irq_top_half,
			vfe_res->bottom_half_handler,
			vfe_res->tasklet_info,
			&tasklet_bh_api);

		if (rsrc_data->irq_err_handle < 1) {
			CAM_ERR(CAM_ISP, "Error IRQ handle subscribe failure");
			rc = -ENOMEM;
			rsrc_data->irq_err_handle = 0;
		}
	}

	CAM_DBG(CAM_ISP, "VFE:%d Start Done", vfe_res->hw_intf->hw_idx);

	return rc;
}

static int cam_vfe_resource_stop(
	struct cam_isp_resource_node *vfe_res)
{
	struct cam_vfe_mux_ver4_data        *vfe_priv;
	int                                        rc = 0;
	uint32_t                                   val = 0;

	if (!vfe_res) {
		CAM_ERR(CAM_ISP, "Error, Invalid input arguments");
		return -EINVAL;
	}

	if ((vfe_res->res_state == CAM_ISP_RESOURCE_STATE_RESERVED) ||
		(vfe_res->res_state == CAM_ISP_RESOURCE_STATE_AVAILABLE))
		return 0;

	vfe_priv = (struct cam_vfe_mux_ver4_data *)vfe_res->res_priv;

	if (vfe_priv->is_lite || !vfe_priv->is_pixel_path)
		goto skip_core_decfg;

	if ((vfe_priv->dsp_mode >= CAM_ISP_DSP_MODE_ONE_WAY) &&
		(vfe_priv->dsp_mode <= CAM_ISP_DSP_MODE_ROUND)) {
		val = cam_io_r_mb(vfe_priv->mem_base +
			vfe_priv->common_reg->core_cfg_0);
		val &= (~(1 << CAM_SHIFT_TOP_CORE_VER_4_CFG_DSP_EN));
		cam_io_w_mb(val, vfe_priv->mem_base +
			vfe_priv->common_reg->core_cfg_0);
	}

skip_core_decfg:
	if (vfe_res->res_state == CAM_ISP_RESOURCE_STATE_STREAMING)
		vfe_res->res_state = CAM_ISP_RESOURCE_STATE_RESERVED;

	val = cam_io_r_mb(vfe_priv->mem_base +
		vfe_priv->common_reg->diag_config);
	if (val & vfe_priv->reg_data->enable_diagnostic_hw) {
		val &= ~vfe_priv->reg_data->enable_diagnostic_hw;
		cam_io_w_mb(val, vfe_priv->mem_base +
			vfe_priv->common_reg->diag_config);
	}

	if (vfe_priv->irq_handle) {
		cam_irq_controller_unsubscribe_irq(
			vfe_priv->vfe_irq_controller, vfe_priv->irq_handle);
		vfe_priv->irq_handle = 0;
	}

	if (vfe_priv->sof_irq_handle) {
		cam_irq_controller_unsubscribe_irq(
			vfe_priv->vfe_irq_controller,
			vfe_priv->sof_irq_handle);
		vfe_priv->sof_irq_handle = 0;
	}

	if (vfe_priv->irq_err_handle) {
		cam_irq_controller_unsubscribe_irq(
			vfe_priv->vfe_irq_controller,
			vfe_priv->irq_err_handle);
		vfe_priv->irq_err_handle = 0;
	}

	return rc;
}

static int cam_vfe_resource_init(
	struct cam_isp_resource_node *vfe_res,
	void *init_args, uint32_t arg_size)
{
	struct cam_vfe_mux_ver4_data          *rsrc_data;
	struct cam_hw_soc_info                *soc_info;
	int                                    rc = 0;

	if (!vfe_res) {
		CAM_ERR(CAM_ISP, "Error Invalid input arguments");
		return -EINVAL;
	}

	rsrc_data = vfe_res->res_priv;
	soc_info = rsrc_data->soc_info;

	if ((rsrc_data->dsp_mode >= CAM_ISP_DSP_MODE_ONE_WAY) &&
		(rsrc_data->dsp_mode <= CAM_ISP_DSP_MODE_ROUND)) {
		rc = cam_vfe_soc_enable_clk(soc_info, CAM_VFE_DSP_CLK_NAME);
		if (rc)
			CAM_ERR(CAM_ISP,
				"failed to enable dsp clk, rc = %d", rc);
	}

	rsrc_data->sof_ts.tv_sec = 0;
	rsrc_data->sof_ts.tv_nsec = 0;
	rsrc_data->epoch_ts.tv_sec = 0;
	rsrc_data->epoch_ts.tv_nsec = 0;
	rsrc_data->eof_ts.tv_sec = 0;
	rsrc_data->eof_ts.tv_nsec = 0;
	rsrc_data->error_ts.tv_sec = 0;
	rsrc_data->error_ts.tv_nsec = 0;

	return rc;
}

static int cam_vfe_resource_deinit(
	struct cam_isp_resource_node        *vfe_res,
	void *deinit_args, uint32_t arg_size)
{
	struct cam_vfe_mux_ver4_data          *rsrc_data;
	struct cam_hw_soc_info                *soc_info;
	int                                    rc = 0;

	if (!vfe_res) {
		CAM_ERR(CAM_ISP, "Error Invalid input arguments");
		return -EINVAL;
	}

	rsrc_data = vfe_res->res_priv;
	soc_info = rsrc_data->soc_info;

	if ((rsrc_data->dsp_mode >= CAM_ISP_DSP_MODE_ONE_WAY) &&
		(rsrc_data->dsp_mode <= CAM_ISP_DSP_MODE_ROUND)) {
		rc = cam_vfe_soc_disable_clk(soc_info, CAM_VFE_DSP_CLK_NAME);
		if (rc)
			CAM_ERR(CAM_ISP, "failed to disable dsp clk");
	}

	return rc;
}

int cam_vfe_res_mux_init(
	struct cam_hw_intf            *hw_intf,
	struct cam_hw_soc_info        *soc_info,
	void                          *vfe_hw_info,
	struct cam_isp_resource_node  *vfe_res,
	void                          *vfe_irq_controller)
{
	struct cam_vfe_mux_ver4_data           *vfe_priv = NULL;
	struct cam_vfe_ver4_path_hw_info       *hw_info = vfe_hw_info;
	struct cam_vfe_soc_private    *soc_priv = soc_info->soc_private;
	int i;

	vfe_priv = kzalloc(sizeof(struct cam_vfe_mux_ver4_data),
		GFP_KERNEL);
	if (!vfe_priv)
		return -ENOMEM;

	vfe_res->res_priv     = vfe_priv;
	vfe_priv->mem_base    = soc_info->reg_map[VFE_CORE_BASE_IDX].mem_base;
	vfe_priv->common_reg  = hw_info->common_reg;
	vfe_priv->reg_data    = hw_info->reg_data;
	vfe_priv->hw_intf     = hw_intf;
	vfe_priv->is_lite     = soc_priv->is_ife_lite;
	vfe_priv->soc_info    = soc_info;
	vfe_priv->vfe_irq_controller = vfe_irq_controller;
	vfe_priv->is_pixel_path = (vfe_res->res_id == CAM_ISP_HW_VFE_IN_CAMIF);
	vfe_priv->module_desc   = hw_info->module_desc;

	vfe_res->init                = cam_vfe_resource_init;
	vfe_res->deinit              = cam_vfe_resource_deinit;
	vfe_res->start               = cam_vfe_resource_start;
	vfe_res->stop                = cam_vfe_resource_stop;
	vfe_res->top_half_handler    = cam_vfe_handle_irq_top_half;
	vfe_res->bottom_half_handler = cam_vfe_handle_irq_bottom_half;

	spin_lock_init(&vfe_priv->spin_lock);
	INIT_LIST_HEAD(&vfe_priv->free_payload_list);
	for (i = 0; i < CAM_VFE_CAMIF_EVT_MAX; i++) {
		INIT_LIST_HEAD(&vfe_priv->evt_payload[i].list);
		list_add_tail(&vfe_priv->evt_payload[i].list,
			&vfe_priv->free_payload_list);
	}
	return 0;
}

int cam_vfe_res_mux_deinit(
	struct cam_isp_resource_node  *vfe_res)
{
	struct cam_vfe_mux_ver4_data *vfe_priv;
	int i = 0;

	if (!vfe_res) {
		CAM_ERR(CAM_ISP, "Error, VFE Node Resource is NULL %pK", vfe_res);
		return -ENODEV;
	}

	vfe_priv = vfe_res->res_priv;

	vfe_res->init                = NULL;
	vfe_res->deinit              = NULL;
	vfe_res->start               = NULL;
	vfe_res->stop                = NULL;
	vfe_res->process_cmd         = NULL;
	vfe_res->top_half_handler    = NULL;
	vfe_res->bottom_half_handler = NULL;
	vfe_res->res_priv            = NULL;

	if (!vfe_priv) {
		CAM_ERR(CAM_ISP, "vfe_priv is NULL %pK", vfe_priv);
		return -ENODEV;
	}

	INIT_LIST_HEAD(&vfe_priv->free_payload_list);
	for (i = 0; i < CAM_VFE_CAMIF_EVT_MAX; i++)
		INIT_LIST_HEAD(&vfe_priv->evt_payload[i].list);
	kfree(vfe_priv);

	return 0;
}

int cam_vfe_top_ver4_init(
	struct cam_hw_soc_info                 *soc_info,
	struct cam_hw_intf                     *hw_intf,
	void                                   *top_hw_info,
	void                                   *vfe_irq_controller,
	struct cam_vfe_top                    **vfe_top_ptr)
{
	int i, j, rc = 0;
	struct cam_vfe_top_ver4_priv           *top_priv = NULL;
	struct cam_vfe_top_ver4_hw_info        *hw_info = top_hw_info;
	struct cam_vfe_top                     *vfe_top;

	vfe_top = kzalloc(sizeof(struct cam_vfe_top), GFP_KERNEL);
	if (!vfe_top) {
		CAM_DBG(CAM_ISP, "Error, Failed to alloc for vfe_top");
		rc = -ENOMEM;
		goto end;
	}

	top_priv = kzalloc(sizeof(struct cam_vfe_top_ver4_priv),
		GFP_KERNEL);
	if (!top_priv) {
		CAM_DBG(CAM_ISP, "Error, Failed to alloc for vfe_top_priv");
		rc = -ENOMEM;
		goto free_vfe_top;
	}

	vfe_top->top_priv = top_priv;
	top_priv->hw_clk_rate = 0;

	if (hw_info->num_mux > CAM_VFE_TOP_MUX_MAX) {
		CAM_ERR(CAM_ISP, "Invalid number of input rsrc: %d, max: %d",
			hw_info->num_mux, CAM_VFE_TOP_MUX_MAX);
		rc = -EINVAL;
		goto free_top_priv;
	}

	top_priv->top_common.num_mux = hw_info->num_mux;

	for (i = 0, j = 0; i < top_priv->top_common.num_mux &&
		j < CAM_VFE_RDI_VER2_MAX; i++) {
		top_priv->top_common.mux_rsrc[i].res_type =
			CAM_ISP_RESOURCE_VFE_IN;
		top_priv->top_common.mux_rsrc[i].hw_intf = hw_intf;
		top_priv->top_common.mux_rsrc[i].res_state =
			CAM_ISP_RESOURCE_STATE_AVAILABLE;
		top_priv->req_clk_rate[i] = 0;

		if (hw_info->mux_type[i] == CAM_VFE_CAMIF_VER_4_0) {
			top_priv->top_common.mux_rsrc[i].res_id =
				CAM_ISP_HW_VFE_IN_CAMIF;

			rc = cam_vfe_res_mux_init(hw_intf, soc_info,
				&hw_info->vfe_full_hw_info,
				&top_priv->top_common.mux_rsrc[i],
				vfe_irq_controller);
		} else if (hw_info->mux_type[i] ==
			CAM_VFE_PDLIB_VER_1_0) {
			/* set the PDLIB resource id */
			top_priv->top_common.mux_rsrc[i].res_id =
				CAM_ISP_HW_VFE_IN_PDLIB;

			rc = cam_vfe_res_mux_init(hw_intf, soc_info,
				&hw_info->pdlib_hw_info,
				&top_priv->top_common.mux_rsrc[i],
				vfe_irq_controller);
		} else if (hw_info->mux_type[i] ==
			CAM_VFE_IN_RD_VER_1_0) {
			/* set the RD resource id */
			top_priv->top_common.mux_rsrc[i].res_id =
				CAM_ISP_HW_VFE_IN_RD;

			rc = cam_vfe_fe_ver1_init(hw_intf, soc_info,
				&hw_info->fe_hw_info,
				&top_priv->top_common.mux_rsrc[i]);
		} else if (hw_info->mux_type[i] ==
			CAM_VFE_RDI_VER_1_0) {
			/* set the RDI resource id */
			top_priv->top_common.mux_rsrc[i].res_id =
				CAM_ISP_HW_VFE_IN_RDI0 + j;

			rc = cam_vfe_res_mux_init(hw_intf, soc_info,
				hw_info->rdi_hw_info[j++],
				&top_priv->top_common.mux_rsrc[i],
				vfe_irq_controller);
		} else if (hw_info->mux_type[i] ==
			CAM_VFE_LCR_VER_1_0) {
			/* set the LCR resource id */
			top_priv->top_common.mux_rsrc[i].res_id =
				CAM_ISP_HW_VFE_IN_LCR;

			rc = cam_vfe_res_mux_init(hw_intf, soc_info,
				&hw_info->lcr_hw_info,
				&top_priv->top_common.mux_rsrc[i],
				vfe_irq_controller);
		} else {
			CAM_WARN(CAM_ISP, "Invalid mux type: %u",
				hw_info->mux_type[i]);
		}
		if (rc)
			goto deinit_resources;
	}


	vfe_top->hw_ops.get_hw_caps = cam_vfe_top_ver4_get_hw_caps;
	vfe_top->hw_ops.init        = cam_vfe_top_ver4_init_hw;
	vfe_top->hw_ops.reset       = cam_vfe_top_ver4_reset;
	vfe_top->hw_ops.reserve     = cam_vfe_top_ver4_reserve;
	vfe_top->hw_ops.release     = cam_vfe_top_ver4_release;
	vfe_top->hw_ops.start       = cam_vfe_top_ver4_start;
	vfe_top->hw_ops.stop        = cam_vfe_top_ver4_stop;
	vfe_top->hw_ops.read        = cam_vfe_top_ver4_read;
	vfe_top->hw_ops.write       = cam_vfe_top_ver4_write;
	vfe_top->hw_ops.process_cmd = cam_vfe_top_ver4_process_cmd;
	*vfe_top_ptr = vfe_top;

	top_priv->common_data.soc_info     = soc_info;
	top_priv->common_data.hw_intf      = hw_intf;
	top_priv->top_common.hw_idx        = hw_intf->hw_idx;
	top_priv->common_data.common_reg   = hw_info->common_reg;

	return rc;

deinit_resources:

	for (--i; i >= 0; i--) {
		if (hw_info->mux_type[i] == CAM_VFE_CAMIF_VER_4_0) {
			if (cam_vfe_res_mux_deinit(
				&top_priv->top_common.mux_rsrc[i]))
				CAM_ERR(CAM_ISP, "Camif Deinit failed");
		} else if (hw_info->mux_type[i] == CAM_VFE_IN_RD_VER_1_0) {
			if (cam_vfe_fe_ver1_deinit(
				&top_priv->top_common.mux_rsrc[i]))
				CAM_ERR(CAM_ISP, "Camif fe Deinit failed");
		} else {
			if (cam_vfe_res_mux_deinit(
				&top_priv->top_common.mux_rsrc[i]))
				CAM_ERR(CAM_ISP,
					"Camif lite res id %d Deinit failed",
					top_priv->top_common.mux_rsrc[i]
					.res_id);
		}
		top_priv->top_common.mux_rsrc[i].res_state =
			CAM_ISP_RESOURCE_STATE_UNAVAILABLE;
	}


free_top_priv:
	kfree(vfe_top->top_priv);
free_vfe_top:
	kfree(vfe_top);
end:
	return rc;
}

int cam_vfe_top_ver4_deinit(struct cam_vfe_top  **vfe_top_ptr)
{
	int i, rc = 0;
	struct cam_vfe_top_ver4_priv           *top_priv = NULL;
	struct cam_vfe_top                     *vfe_top;

	if (!vfe_top_ptr) {
		CAM_ERR(CAM_ISP, "Error, Invalid input");
		return -EINVAL;
	}

	vfe_top = *vfe_top_ptr;
	if (!vfe_top) {
		CAM_ERR(CAM_ISP, "Error, vfe_top NULL");
		return -ENODEV;
	}

	top_priv = vfe_top->top_priv;
	if (!top_priv) {
		CAM_ERR(CAM_ISP, "Error, vfe_top_priv NULL");
		rc = -ENODEV;
		goto free_vfe_top;
	}

	for (i = 0; i < top_priv->top_common.num_mux; i++) {
		top_priv->top_common.mux_rsrc[i].res_state =
			CAM_ISP_RESOURCE_STATE_UNAVAILABLE;
		if (top_priv->top_common.mux_rsrc[i].res_type ==
			CAM_VFE_CAMIF_VER_4_0) {
			rc = cam_vfe_res_mux_deinit(
				&top_priv->top_common.mux_rsrc[i]);
			if (rc)
				CAM_ERR(CAM_ISP, "Camif deinit failed rc=%d",
					rc);
		} else if (top_priv->top_common.mux_rsrc[i].res_type ==
			CAM_VFE_IN_RD_VER_1_0) {
			rc = cam_vfe_fe_ver1_deinit(
				&top_priv->top_common.mux_rsrc[i]);
			if (rc)
				CAM_ERR(CAM_ISP, "Camif deinit failed rc=%d",
					rc);
		} else {
			rc = cam_vfe_res_mux_deinit(
				&top_priv->top_common.mux_rsrc[i]);
			if (rc)
				CAM_ERR(CAM_ISP,
					"Camif lite res id %d Deinit failed",
					top_priv->top_common.mux_rsrc[i]
					.res_id);
		}
	}

	kfree(vfe_top->top_priv);

free_vfe_top:
	kfree(vfe_top);
	*vfe_top_ptr = NULL;

	return rc;
}
