// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
 */

#include <linux/iopoll.h>
#include <linux/slab.h>
#include <media/cam_tfe.h>
#include <media/cam_defs.h>

#include "cam_top_tpg_core.h"
#include "cam_soc_util.h"
#include "cam_io_util.h"
#include "cam_debug_util.h"
#include "cam_top_tpg_ver3.h"

static int cam_top_tpg_ver3_get_hw_caps(
	void                                         *hw_priv,
	void                                         *get_hw_cap_args,
	uint32_t                                      arg_size)
{
	int                                           rc = 0;
	struct cam_top_tpg_hw_caps                   *hw_caps;
	struct cam_top_tpg_hw                        *tpg_hw;
	const struct cam_top_tpg_ver3_reg_offset     *tpg_reg;
	struct cam_hw_info                           *tpg_hw_info;

	if (!hw_priv || !get_hw_cap_args) {
		CAM_ERR(CAM_ISP, "TPG: Invalid args");
		return -EINVAL;
	}

	tpg_hw_info = (struct cam_hw_info  *)hw_priv;
	tpg_hw = (struct cam_top_tpg_hw   *)tpg_hw_info->core_info;
	hw_caps = (struct cam_top_tpg_hw_caps *) get_hw_cap_args;
	tpg_reg = tpg_hw->tpg_info->tpg_reg;

	hw_caps->major_version = tpg_reg->major_version;
	hw_caps->minor_version = tpg_reg->minor_version;
	hw_caps->version_incr = tpg_reg->version_incr;

	CAM_DBG(CAM_ISP,
		"TPG:%d major:%d minor:%d ver :%d",
		tpg_hw->hw_intf->hw_idx, hw_caps->major_version,
		hw_caps->minor_version, hw_caps->version_incr);

	return rc;
}

static int cam_top_tpg_ver3_print_reserved_vcdt(
	struct cam_top_tpg_hw                  *tpg_hw)
{
	struct cam_top_tpg_cfg_v2              *tpg_data;
	int                                     i, j;

	if (!tpg_hw)
		return -EINVAL;

	tpg_data = (struct cam_top_tpg_cfg_v2 *)tpg_hw->tpg_res.res_priv;
	CAM_INFO(CAM_ISP, "tpg:%d Active_VCs: %d",
		tpg_hw->hw_intf->hw_idx, tpg_data->num_active_vcs);

	for (i = 0; i < tpg_data->num_active_vcs; i++)
	{
		CAM_INFO(CAM_ISP, "VC[%d]: 0x%x", i, tpg_data->vc_dt[i].vc_num);

		for (j = 0; j < tpg_data->vc_dt[i].num_active_dts; j++)
		{
			CAM_INFO(CAM_ISP, "DT[%d]: 0x%x", j,
				tpg_data->vc_dt[i].dt_cfg[j].data_type);
		}
	}

	return 0;
}


static int cam_top_tpg_ver3_process_cmd(void *hw_priv,
	uint32_t cmd_type, void *cmd_args, uint32_t arg_size)
{
	int                                     rc = 0;
	struct cam_top_tpg_hw                  *tpg_hw;
	struct cam_hw_info                     *tpg_hw_info;
	struct cam_isp_tpg_core_config         *core_cfg;
	struct cam_top_tpg_cfg_v2              *tpg_data;

	if (!hw_priv || !cmd_args) {
		CAM_ERR(CAM_ISP, "TPG: Invalid args");
		return -EINVAL;
	}

	tpg_hw_info = (struct cam_hw_info *)hw_priv;
	tpg_hw = (struct cam_top_tpg_hw *)tpg_hw_info->core_info;
	tpg_data = (struct cam_top_tpg_cfg_v2 *)tpg_hw->tpg_res.res_priv;

	switch (cmd_type) {
	case CAM_ISP_HW_CMD_TPG_CORE_CFG_CMD:
		if (arg_size != sizeof(struct cam_isp_tpg_core_config)) {
			CAM_ERR(CAM_ISP, "Invalid size %u expected %u",
				arg_size,
				sizeof(struct cam_isp_tpg_core_config));
			rc = -EINVAL;
			break;
		}

		core_cfg = (struct cam_isp_tpg_core_config *)cmd_args;
		tpg_data->pix_pattern = core_cfg->pix_pattern;
		tpg_data->vc_dt_pattern_id = core_cfg->vc_dt_pattern_id;
		tpg_data->qcfa_en = core_cfg->qcfa_en;
		tpg_data->h_blank_count = core_cfg->hbi_clk_cnt;
		tpg_data->v_blank_count = core_cfg->vbi_clk_cnt;
		if (core_cfg->throttle_pattern <= 0xFFFF)
			tpg_data->throttle_pattern = core_cfg->throttle_pattern;

		CAM_DBG(CAM_ISP,
			"pattern_id: 0x%x pix_pattern: 0x%x qcfa_en: 0x%x hbi: 0x%x vbi: 0x%x throttle: 0x%x",
			tpg_data->vc_dt_pattern_id, tpg_data->pix_pattern,
			tpg_data->qcfa_en, tpg_data->h_blank_count,
			tpg_data->v_blank_count, tpg_data->throttle_pattern);
		break;
	default:
		CAM_ERR(CAM_ISP, "Invalid TPG cmd type %u", cmd_type);
		rc = -EINVAL;
		break;
	}

	return rc;
}

static int cam_top_tpg_ver3_add_append_vc_dt_info(uint32_t *num_active_vcs,
	struct cam_top_tpg_vc_dt_info *tpg_vcdt,
	struct cam_isp_in_port_generic_info *in_port)
{
	bool                                    is_dt_saved = false;
	int                                     i;
	int                                     j;
	uint32_t                               *num_dts;
	uint32_t                                encode_format;
	int                                     rc;

	for (i = 0; i < in_port->num_valid_vc_dt; i++) {
		if (in_port->dt[i] > 0x3f || in_port->vc[i] > 0x1f) {
			CAM_ERR(CAM_ISP, "Invalid vc:%d dt %d",
				in_port->vc[i],
				in_port->dt[i]);
			return -EINVAL;
		}
		rc = cam_top_tpg_get_format(in_port->format, &encode_format);
		if (rc)
			return rc;

		for (j = 0; j < *num_active_vcs; j++) {
			if (tpg_vcdt[j].vc_num == in_port->vc[i]) {
				num_dts = &tpg_vcdt[j].num_active_dts;
				if (*num_dts >=
					CAM_TOP_TPG_MAX_SUPPORTED_DT) {
					CAM_ERR(CAM_ISP,
						"Cannot support more than 4 DTs per VC"
						);
					return -EINVAL;
				}
				tpg_vcdt[j].dt_cfg[*num_dts].data_type =
					in_port->dt[i];
				tpg_vcdt[j].dt_cfg[*num_dts].encode_format =
					encode_format;
				tpg_vcdt[j].dt_cfg[*num_dts].frame_height =
					in_port->height;
				if (in_port->usage_type)
					tpg_vcdt[j].dt_cfg[*num_dts].frame_width
					= ((in_port->right_stop -
						in_port->left_start) + 1);
				else
					tpg_vcdt[j].dt_cfg[*num_dts].frame_width
					= in_port->left_width;

				CAM_DBG(CAM_ISP,
					"vc:%d dt:%d format:%d height:%d width:%d",
					in_port->vc[i], in_port->dt[i],
					encode_format, in_port->height,
					tpg_vcdt[j].dt_cfg[*num_dts].frame_width
					);

				*num_dts += 1;
				is_dt_saved = true;
				break;
			}
		}

		if (is_dt_saved == false) {
			if (*num_active_vcs >= CAM_TOP_TPG_MAX_SUPPORTED_VC) {
				CAM_ERR(CAM_ISP,
					"Cannot support more than 4 VCs");
				return -EINVAL;
			}

			tpg_vcdt[*num_active_vcs].vc_num = in_port->vc[i];
			tpg_vcdt[*num_active_vcs].dt_cfg[0].data_type =
				in_port->dt[i];
			tpg_vcdt[*num_active_vcs].dt_cfg[0].encode_format =
				encode_format;
			tpg_vcdt[*num_active_vcs].dt_cfg[0].frame_height =
				in_port->height;

			if (in_port->usage_type)
				tpg_vcdt[*num_active_vcs].dt_cfg[0].frame_width
				= ((in_port->right_stop - in_port->left_start)
					+ 1);
			else
				tpg_vcdt[*num_active_vcs].dt_cfg[0].frame_width
				= in_port->left_width;

			CAM_DBG(CAM_ISP,
				"vc:%d dt:%d format:%d height:%d width:%d",
				in_port->vc[i], in_port->dt[i],
				encode_format, in_port->height,
				tpg_vcdt[*num_active_vcs].dt_cfg[0].frame_width
				);

			tpg_vcdt[*num_active_vcs].num_active_dts++;
			*num_active_vcs += 1;
		} else {
			is_dt_saved = false;
		}
	}
	return 0;
}

static int cam_top_tpg_ver3_reserve(
	void                                         *hw_priv,
	void                                         *reserve_args,
	uint32_t                                      arg_size)
{
	int                                           rc = 0;
	struct cam_top_tpg_hw                        *tpg_hw;
	struct cam_hw_info                           *tpg_hw_info;
	struct cam_top_tpg_reserve_args              *reserv;
	struct cam_top_tpg_cfg_v2                    *tpg_data;
	struct cam_top_tpg_vc_dt_info
		in_port_vc_dt[CAM_TOP_TPG_MAX_SUPPORTED_VC];
	const struct cam_top_tpg_debugfs             *tpg_debug = NULL;
	uint32_t                                      num_active_vcs = 0;
	int                                           i;

	if (!hw_priv || !reserve_args || (arg_size !=
		sizeof(struct cam_top_tpg_reserve_args))) {
		CAM_ERR(CAM_ISP, "TPG: Invalid args");
		return -EINVAL;
	}

	tpg_hw_info = (struct cam_hw_info *)hw_priv;
	tpg_hw = (struct cam_top_tpg_hw *)tpg_hw_info->core_info;
	reserv = (struct cam_top_tpg_reserve_args  *)reserve_args;

	mutex_lock(&tpg_hw->hw_info->hw_mutex);

	tpg_debug = cam_top_tpg_get_debugfs();

	if ((reserv->in_port[0]->lane_num <= 0 ||
		reserv->in_port[0]->lane_num > 4) ||
		(reserv->in_port[0]->lane_type >= 2)) {
		CAM_ERR_RATE_LIMIT(CAM_ISP, "TPG:%u invalid input %d %d",
			tpg_hw->hw_intf->hw_idx,
			reserv->in_port[0]->lane_num,
			reserv->in_port[0]->lane_type);
		rc = -EINVAL;
		goto error;
	}

	tpg_data = (struct cam_top_tpg_cfg_v2 *)tpg_hw->tpg_res.res_priv;

	memcpy((void *)&in_port_vc_dt[0], (void *)&tpg_data->vc_dt[0],
		CAM_TOP_TPG_MAX_SUPPORTED_VC *
		sizeof(struct cam_top_tpg_vc_dt_info));
	num_active_vcs = tpg_data->num_active_vcs;

	for (i = 0; i < reserv->num_inport; i++) {
		if (tpg_data->num_active_vcs) {
			if ((tpg_data->phy_sel !=
				reserv->in_port[i]->lane_type) ||
				(tpg_data->num_active_lanes !=
					reserv->in_port[i]->lane_num)) {
				CAM_ERR_RATE_LIMIT(CAM_ISP,
					"TPG: %u invalid DT config for tpg",
					tpg_hw->hw_intf->hw_idx);
				rc = -EINVAL;
				goto error;
			}
		} else {
			tpg_data->phy_sel = reserv->in_port[0]->lane_type;
			tpg_data->num_active_lanes =
				reserv->in_port[0]->lane_num;
		}

		rc = cam_top_tpg_ver3_add_append_vc_dt_info(
				&num_active_vcs,
				&in_port_vc_dt[0],
				reserv->in_port[i]);
		if (rc) {
			rc = -EINVAL;
			CAM_ERR(CAM_ISP,
				"Failed to reserve TPG:%u for in_port: %u",
				tpg_hw->hw_intf->hw_idx, i);
			goto error;
		}
	}

	CAM_DBG(CAM_ISP, "TPG: %u enter", tpg_hw->hw_intf->hw_idx);

	tpg_data->num_active_vcs = num_active_vcs;
	memcpy((void *)&tpg_data->vc_dt[0], (void *)&in_port_vc_dt[0],
		CAM_TOP_TPG_MAX_SUPPORTED_VC *
		sizeof(struct cam_top_tpg_vc_dt_info));

	CAM_DBG(CAM_ISP,
		"TPG:%u phy:%d lines:%d pattern:%d hbi: %d vbi: %d",
		tpg_hw->hw_intf->hw_idx,
		tpg_data->phy_sel,
		tpg_data->num_active_lanes,
		tpg_data->pix_pattern,
		tpg_data->h_blank_count,
		tpg_data->v_blank_count);

	reserv->node_res = &tpg_hw->tpg_res;
	tpg_hw->tpg_res.res_state = CAM_ISP_RESOURCE_STATE_RESERVED;
error:
	if ((tpg_debug != NULL) && tpg_debug->enable_vcdt_dump)
		cam_top_tpg_ver3_print_reserved_vcdt(tpg_hw);
	mutex_unlock(&tpg_hw->hw_info->hw_mutex);
	CAM_DBG(CAM_ISP, "exit rc %u", rc);

	return rc;
}

static int cam_top_tpg_ver3_release(void *hw_priv,
	void *release_args, uint32_t arg_size)
{
	int rc = 0;
	struct cam_top_tpg_hw           *tpg_hw;
	struct cam_hw_info              *tpg_hw_info;
	struct cam_top_tpg_cfg_v2       *tpg_data;
	struct cam_isp_resource_node    *tpg_res;

	if (!hw_priv || !release_args ||
		(arg_size != sizeof(struct cam_isp_resource_node))) {
		CAM_ERR(CAM_ISP, "TPG: Invalid args");
		return -EINVAL;
	}

	tpg_hw_info = (struct cam_hw_info  *)hw_priv;
	tpg_hw = (struct cam_top_tpg_hw   *)tpg_hw_info->core_info;
	tpg_res = (struct cam_isp_resource_node *)release_args;

	mutex_lock(&tpg_hw->hw_info->hw_mutex);
	if ((tpg_res->res_type != CAM_ISP_RESOURCE_TPG) ||
		(tpg_res->res_state <= CAM_ISP_RESOURCE_STATE_AVAILABLE)) {
		CAM_ERR(CAM_ISP, "TPG:%d Invalid res type:%d res_state:%d",
			tpg_hw->hw_intf->hw_idx, tpg_res->res_type,
			tpg_res->res_state);
		rc = -EINVAL;
		goto end;
	}

	CAM_DBG(CAM_ISP, "TPG:%d res type :%d",
		tpg_hw->hw_intf->hw_idx, tpg_res->res_type);

	tpg_res->res_state = CAM_ISP_RESOURCE_STATE_AVAILABLE;
	tpg_data = (struct cam_top_tpg_cfg_v2 *)tpg_res->res_priv;
	memset(tpg_data, 0, sizeof(struct cam_top_tpg_cfg_v2));

end:
	mutex_unlock(&tpg_hw->hw_info->hw_mutex);
	return rc;
}

static int cam_top_tpg_ver3_start(
	void                                         *hw_priv,
	void                                         *start_args,
	uint32_t                                      arg_size)
{
	int                                           rc = 0;
	struct cam_top_tpg_hw                        *tpg_hw;
	struct cam_hw_info                           *tpg_hw_info;
	struct cam_hw_soc_info                       *soc_info;
	struct cam_isp_resource_node                 *tpg_res;
	struct cam_top_tpg_ver3_reg_offset           *tpg_reg;
	struct cam_top_tpg_cfg_v2                    *tpg_data;
	struct cam_top_tpg_vc_dt_info                *vc_dt;
	uint32_t                                      i, val, j;

	if (!hw_priv || !start_args ||
		(arg_size != sizeof(struct cam_isp_resource_node))) {
		CAM_ERR(CAM_ISP, "TPG: Invalid args");
		return -EINVAL;
	}

	tpg_hw_info = (struct cam_hw_info  *)hw_priv;
	tpg_hw = (struct cam_top_tpg_hw   *)tpg_hw_info->core_info;
	tpg_reg = tpg_hw->tpg_info->tpg_reg;
	tpg_res = (struct cam_isp_resource_node *)start_args;
	tpg_data = (struct cam_top_tpg_cfg_v2  *)tpg_res->res_priv;
	soc_info = &tpg_hw->hw_info->soc_info;

	if ((tpg_res->res_type != CAM_ISP_RESOURCE_TPG) ||
		(tpg_res->res_state != CAM_ISP_RESOURCE_STATE_RESERVED)) {
		CAM_ERR(CAM_ISP, "TPG:%d Invalid Res type:%d res_state:%d",
			tpg_hw->hw_intf->hw_idx,
			tpg_res->res_type, tpg_res->res_state);
		rc = -EINVAL;
		goto end;
	}

	cam_io_w_mb(1, soc_info->reg_map[0].mem_base + tpg_reg->tpg_top_clear);

	for (i = 0; i < tpg_data->num_active_vcs; i++) {
		vc_dt = &tpg_data->vc_dt[i];

		val = (1 << tpg_reg->tpg_split_en_shift);
		val |= tpg_data->pix_pattern;
		if (tpg_data->qcfa_en)
			val |=
			(1 << tpg_reg->tpg_color_bar_qcfa_en_shift);
		cam_io_w_mb(val, soc_info->reg_map[0].mem_base +
			tpg_reg->tpg_vc0_color_bar_cfg + (0x60 * i));
		CAM_DBG(CAM_ISP, "vc%d_color_bar_cfg: 0x%x", i, val);

		if (tpg_data->h_blank_count)
			val = tpg_data->h_blank_count;
		else
			val = 0x40;
		cam_io_w_mb(val, soc_info->reg_map[0].mem_base +
			tpg_reg->tpg_vc0_hbi_cfg + (0x60 * i));
		CAM_DBG(CAM_ISP, "vc%d_hbi_cfg: 0x%x", i, val);

		if (tpg_data->v_blank_count)
			val = tpg_data->v_blank_count;
		else
			val = 0xC600;
		cam_io_w_mb(val, soc_info->reg_map[0].mem_base +
			tpg_reg->tpg_vc0_vbi_cfg + (0x60 * i));
		CAM_DBG(CAM_ISP, "vc%d_vbi_cgf: 0x%x", i, val);

		cam_io_w_mb(CAM_TPG_LFSR_SEED,
			soc_info->reg_map[0].mem_base +
			tpg_reg->tpg_vc0_lfsr_seed + (0x60 * i));

		val = (((vc_dt->num_active_dts-1) <<
			tpg_reg->tpg_num_dts_shift_val) |
			vc_dt->vc_num);
		cam_io_w_mb(val, soc_info->reg_map[0].mem_base +
			tpg_reg->tpg_vc0_cfg0 + (0x60 * i));
		CAM_DBG(CAM_ISP, "vc%d_cfg0: 0x%x", i, val);

		for (j = 0; j < vc_dt->num_active_dts; j++) {
			val = (((vc_dt->dt_cfg[j].frame_width & 0xFFFF) << 16) |
				(vc_dt->dt_cfg[j].frame_height & 0xFFFF));
			cam_io_w_mb(val, soc_info->reg_map[0].mem_base +
				tpg_reg->tpg_vc0_dt_0_cfg_0 +
				(0x60 * i) + (j * 0x0c));
			CAM_DBG(CAM_ISP, "vc%d_dt%d_cfg_0: 0x%x", i, j, val);

			cam_io_w_mb(vc_dt->dt_cfg[j].data_type,
				soc_info->reg_map[0].mem_base +
				tpg_reg->tpg_vc0_dt_0_cfg_1 +
				(0x60 * i) + (j * 0x0c));
			CAM_DBG(CAM_ISP, "vc%d_dt%d_cfg_1: 0x%x",
				i, j, vc_dt->dt_cfg[j].data_type);

			val = ((vc_dt->dt_cfg[j].encode_format & 0xF) <<
				tpg_reg->tpg_dt_encode_format_shift) |
				tpg_reg->tpg_payload_mode_color;
			cam_io_w_mb(val, soc_info->reg_map[0].mem_base +
				tpg_reg->tpg_vc0_dt_0_cfg_2 +
				(0x60 * i) + (j * 0x0c));
			CAM_DBG(CAM_ISP, "vc%d_dt%d_cfg_2: 0x%x", i, j, val);
		}
	}

	if (tpg_data->throttle_pattern)
		val = tpg_data->throttle_pattern;
	else
		val = 0x1111;
	cam_io_w_mb(val, soc_info->reg_map[0].mem_base + tpg_reg->tpg_throttle);
	CAM_DBG(CAM_ISP, "tpg_throttle: 0x%x", val);

	cam_io_w_mb(1, soc_info->reg_map[0].mem_base +
		tpg_reg->tpg_top_irq_mask);

	val = ((tpg_data->num_active_vcs - 1) <<
		(tpg_reg->tpg_num_active_vcs_shift) |
		(tpg_data->num_active_lanes - 1) <<
		tpg_reg->tpg_num_active_lanes_shift) |
		(tpg_data->vc_dt_pattern_id) <<
		(tpg_reg->tpg_vc_dt_pattern_id_shift) |
		(tpg_data->phy_sel << tpg_reg->tpg_cphy_dphy_sel_shift_val) |
		(1 << tpg_reg->tpg_en_shift_val);
	cam_io_w_mb(val, soc_info->reg_map[0].mem_base + tpg_reg->tpg_ctrl);
	CAM_DBG(CAM_ISP, "tpg_ctrl 0x%x", val);

	tpg_res->res_state = CAM_ISP_RESOURCE_STATE_STREAMING;

	val = cam_io_r_mb(soc_info->reg_map[0].mem_base +
		tpg_reg->tpg_hw_version);
	CAM_DBG(CAM_ISP, "TPG:%d TPG HW version: 0x%x started",
		tpg_hw->hw_intf->hw_idx, val);

end:
	return rc;
}

static int cam_top_tpg_ver3_stop(
	void                                         *hw_priv,
	void                                         *stop_args,
	uint32_t                                      arg_size)
{
	int                                           rc = 0;
	struct cam_top_tpg_hw                        *tpg_hw;
	struct cam_hw_info                           *tpg_hw_info;
	struct cam_hw_soc_info                       *soc_info;
	struct cam_isp_resource_node                 *tpg_res;
	const struct cam_top_tpg_ver3_reg_offset     *tpg_reg;

	if (!hw_priv || !stop_args ||
		(arg_size != sizeof(struct cam_isp_resource_node))) {
		CAM_ERR(CAM_ISP, "TPG: Invalid args");
		return -EINVAL;
	}

	tpg_hw_info = (struct cam_hw_info  *)hw_priv;
	tpg_hw = (struct cam_top_tpg_hw   *)tpg_hw_info->core_info;
	tpg_reg = tpg_hw->tpg_info->tpg_reg;
	tpg_res = (struct cam_isp_resource_node  *) stop_args;
	soc_info = &tpg_hw->hw_info->soc_info;

	if ((tpg_res->res_type != CAM_ISP_RESOURCE_TPG) ||
		(tpg_res->res_state != CAM_ISP_RESOURCE_STATE_STREAMING)) {
		CAM_DBG(CAM_ISP, "TPG:%d Invalid Res type:%d res_state:%d",
			tpg_hw->hw_intf->hw_idx,
			tpg_res->res_type, tpg_res->res_state);
		rc = -EINVAL;
		goto end;
	}

	cam_io_w_mb(0, soc_info->reg_map[0].mem_base + tpg_reg->tpg_ctrl);

	cam_io_w_mb(0, soc_info->reg_map[0].mem_base +
		tpg_reg->tpg_top_irq_mask);

	cam_io_w_mb(1, soc_info->reg_map[0].mem_base +
		tpg_reg->tpg_top_irq_clear);

	cam_io_w_mb(1, soc_info->reg_map[0].mem_base +
		tpg_reg->tpg_top_irq_cmd);

	cam_io_w_mb(1, soc_info->reg_map[0].mem_base + tpg_reg->tpg_top_clear);

	tpg_res->res_state = CAM_ISP_RESOURCE_STATE_RESERVED;

	CAM_DBG(CAM_ISP, "TPG:%d stopped", tpg_hw->hw_intf->hw_idx);
end:
	return rc;
}

int cam_top_tpg_ver3_init(
	struct cam_top_tpg_hw                        *tpg_hw)
{
	tpg_hw->hw_intf->hw_ops.get_hw_caps = cam_top_tpg_ver3_get_hw_caps;
	tpg_hw->hw_intf->hw_ops.reserve     = cam_top_tpg_ver3_reserve;
	tpg_hw->hw_intf->hw_ops.release     = cam_top_tpg_ver3_release;
	tpg_hw->hw_intf->hw_ops.start       = cam_top_tpg_ver3_start;
	tpg_hw->hw_intf->hw_ops.stop        = cam_top_tpg_ver3_stop;
	tpg_hw->hw_intf->hw_ops.process_cmd = cam_top_tpg_ver3_process_cmd;

	cam_top_tpg_debug_register();
	return 0;
}
