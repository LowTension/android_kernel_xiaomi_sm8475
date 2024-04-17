/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 * Copyright (c) 2020 XiaoMi, Inc. All rights reserved.
 */

#define pr_fmt(fmt)	"mi-disp-parse:[%s:%d] " fmt, __func__, __LINE__
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>

#include "mi_disp_print.h"
#include "dsi_panel.h"
#include "dsi_parser.h"
#include "mi_panel_id.h"
#include <linux/soc/qcom/smem.h>

#define DEFAULT_MAX_BRIGHTNESS_CLONE 4095
#define SMEM_SW_DISPLAY_LHBM_TABLE 498
#define SMEM_SW_DISPLAY_GRAY_SCALE_TABLE 499
#define SMEM_SW_DISPLAY_LOCKDOWN_TABLE 500

int mi_dsi_panel_parse_esd_gpio_config(struct dsi_panel *panel)
{
	int rc = 0;
	struct dsi_parser_utils *utils = &panel->utils;
	struct mi_dsi_panel_cfg *mi_cfg = &panel->mi_cfg;

	mi_cfg->esd_err_irq_gpio = of_get_named_gpio_flags(
			utils->data, "mi,esd-err-irq-gpio",
			0, (enum of_gpio_flags *)&(mi_cfg->esd_err_irq_flags));
	if (gpio_is_valid(mi_cfg->esd_err_irq_gpio)) {
		mi_cfg->esd_err_irq = gpio_to_irq(mi_cfg->esd_err_irq_gpio);
		rc = gpio_request(mi_cfg->esd_err_irq_gpio, "esd_err_irq_gpio");
		if (rc)
			DISP_ERROR("Failed to request esd irq gpio %d, rc=%d\n",
				mi_cfg->esd_err_irq_gpio, rc);
		else
			gpio_direction_input(mi_cfg->esd_err_irq_gpio);
	} else {
		rc = -EINVAL;
	}

	if( !strcmp(panel->name,"xiaomi m80 42 02 0a video mode dual dsi dphy panel")){
		mi_cfg->esd_err_irq_gpio_second = of_get_named_gpio_flags(
			utils->data, "mi,esd-err-irq-gpio-second",
			0, (enum of_gpio_flags *)&(mi_cfg->esd_err_irq_flags_second));
		if (gpio_is_valid(mi_cfg->esd_err_irq_gpio_second)) {
			mi_cfg->esd_err_irq_second = gpio_to_irq(mi_cfg->esd_err_irq_gpio_second);
			rc = gpio_request(mi_cfg->esd_err_irq_gpio_second, "esd_err_irq_gpio_second");
			if (rc)
				DISP_ERROR("Failed to request esd irq gpio second %d, rc=%d\n",
					mi_cfg->esd_err_irq_gpio_second, rc);
			else
				gpio_direction_input(mi_cfg->esd_err_irq_gpio_second);
		} else {
			rc = -EINVAL;
		}
	}
	
	return rc;
}

static void mi_dsi_panel_parse_round_corner_config(struct dsi_panel *panel)
{
	struct dsi_parser_utils *utils = &panel->utils;
	struct mi_dsi_panel_cfg *mi_cfg = &panel->mi_cfg;

	mi_cfg->ddic_round_corner_enabled =
			utils->read_bool(utils->data, "mi,ddic-round-corner-enabled");
	if (mi_cfg->ddic_round_corner_enabled)
		DISP_INFO("mi,ddic-round-corner-enabled is defined\n");
}

static void mi_dsi_panel_parse_lhbm_config(struct dsi_panel *panel)
{
	int rc = 0;
	int i  = 0, tmp = 0;
	size_t item_size;
	void *lhbm_ptr = NULL;

	struct dsi_parser_utils *utils = &panel->utils;
	struct mi_dsi_panel_cfg *mi_cfg = &panel->mi_cfg;

	mi_cfg->local_hbm_enabled =
			utils->read_bool(utils->data, "mi,local-hbm-enabled");
	if (mi_cfg->local_hbm_enabled)
		DISP_INFO("local hbm feature enabled\n");

	rc = utils->read_u32(utils->data, "mi,local-hbm-ui-ready-delay-num-frame",
			&mi_cfg->lhbm_ui_ready_delay_frame);
	if (rc)
		mi_cfg->lhbm_ui_ready_delay_frame = 0;
	DISP_INFO("local hbm ui_ready delay %d frame\n",
			mi_cfg->lhbm_ui_ready_delay_frame);

	mi_cfg->need_fod_animal_in_normal =
			utils->read_bool(utils->data, "mi,need-fod-animal-in-normal-enabled");
	if (mi_cfg->need_fod_animal_in_normal)
		DISP_INFO("need fod animal in normal enabled\n");


	mi_cfg->lhbm_g500_update_flag =
			utils->read_bool(utils->data, "mi,local-hbm-green-500nit-update-flag");
	if (mi_cfg->lhbm_g500_update_flag)
		DISP_INFO("mi,local-hbm-green-500nit-update-flag\n");

	mi_cfg->lhbm_w1000_update_flag =
			utils->read_bool(utils->data, "mi,local-hbm-white-1000nit-update-flag");
	if (mi_cfg->lhbm_w1000_update_flag)
		DISP_INFO("mi,local-hbm-white-1000nit-update-flag\n");

	mi_cfg->lhbm_w110_update_flag =
			utils->read_bool(utils->data, "mi,local-hbm-white-110nit-update-flag");
	if (mi_cfg->lhbm_w110_update_flag)
		DISP_INFO("mi,local-hbm-white-110nit-update-flag\n");

	mi_cfg->lhbm_alpha_ctrlaa =
			utils->read_bool(utils->data, "mi,local-hbm-alpha-ctrl-aa-area");
	if (mi_cfg->lhbm_alpha_ctrlaa)
		DISP_INFO("mi,local-hbm-alpha-ctrl-aa-area\n");

	mi_cfg->lhbm_ctrl_df_reg =
			utils->read_bool(utils->data, "mi,local-hbm-ctrl-df-reg");
	if (mi_cfg->lhbm_ctrl_df_reg)
		DISP_INFO("mi,local-hbm-ctrl-df-reg\n");

	mi_cfg->lhbm_ctrl_b2_reg =
			utils->read_bool(utils->data, "mi,local-hbm-ctrl-b2-reg");
	if (mi_cfg->lhbm_ctrl_b2_reg)
		DISP_INFO("mi,local-hbm-ctrl-b2-reg\n");

	mi_cfg->lhbm_ctrl_63_C5_reg =
			utils->read_bool(utils->data, "mi,local-hbm-ctrl-63-c5-reg");
	if (mi_cfg->lhbm_ctrl_63_C5_reg)
		DISP_INFO("mi,local-hbm-ctrl-63-c5-reg\n");

	if (mi_get_panel_id(panel->mi_cfg.mi_panel_id) == L3_PANEL_PA ||
			mi_get_panel_id(panel->mi_cfg.mi_panel_id) == L12_PANEL_PA ||
			mi_get_panel_id(panel->mi_cfg.mi_panel_id) == L12_PANEL_PB ||
			mi_get_panel_id(panel->mi_cfg.mi_panel_id) == L3S_PANEL_PA ||
			mi_get_panel_id(panel->mi_cfg.mi_panel_id) == L9S_PANEL_PA ||
			mi_get_panel_id(panel->mi_cfg.mi_panel_id) == L9S_PANEL_PB ||
			mi_get_panel_id(panel->mi_cfg.mi_panel_id) == M11A_PANEL_PA||
			mi_get_panel_id(panel->mi_cfg.mi_panel_id) == N16_PANEL_PA ||
			mi_get_panel_id(panel->mi_cfg.mi_panel_id) == N16_PANEL_PB) {
		lhbm_ptr = qcom_smem_get(QCOM_SMEM_HOST_ANY, SMEM_SW_DISPLAY_LHBM_TABLE, &item_size);
		if (!IS_ERR(lhbm_ptr) && item_size > 0) {
			DISP_INFO("lhbm data size %d\n", item_size);
			memcpy(mi_cfg->lhbm_rgb_param, lhbm_ptr, item_size);
			for (i = 1; i < item_size; i += 2) {
				tmp = ((mi_cfg->lhbm_rgb_param[i-1]) << 8) | mi_cfg->lhbm_rgb_param[i];
				DISP_INFO("index %d = 0x%04X\n", i, tmp);
				if (tmp == 0x0000 && mi_get_panel_id(panel->mi_cfg.mi_panel_id) != N16_PANEL_PA) {
					DISP_INFO("uefi read lhbm data failed, need kernel read!\n");
					mi_cfg->uefi_read_lhbm_success = false;
					break;
				} else {
					mi_cfg->uefi_read_lhbm_success = true;
				}
			}
		}
	}

}

static void mi_dsi_panel_parse_lockdown_config(struct dsi_panel *panel)
{
	size_t item_size;
	void *lockdown_ptr = NULL;
	struct mi_dsi_panel_cfg *mi_cfg = &panel->mi_cfg;

	int i =0;
	DISP_ERROR("lockdown kernel  debug start !! \n");
	if (mi_get_panel_id(panel->mi_cfg.mi_panel_id) == M80_PANEL_PA) {
		DISP_ERROR("M80 product lockdown kernel get !! \n");
		lockdown_ptr = qcom_smem_get(QCOM_SMEM_HOST_ANY, SMEM_SW_DISPLAY_LOCKDOWN_TABLE, &item_size);
		if (!IS_ERR(lockdown_ptr) && item_size > 0) {
			DISP_ERROR("M80 lockdown data size= %d\n",item_size);
			memcpy(mi_cfg->lockdown_cfg.lockdown_param, lockdown_ptr, item_size);
		}
		for (i=0; i<8 ; i++)
		{
			DISP_ERROR("M80 lockdown data mi_cfg->lockdown_cfg.lockdown_param[%d] = 0x%0x\n",i, mi_cfg->lockdown_cfg.lockdown_param[i]);
		}
	}
}

static void mi_dsi_panel_parse_gray_scale_config(struct dsi_panel *panel)
{
	int i  = 0, tmp = 0;
	size_t item_size;
	void *gray_scale_ptr = NULL;
	struct mi_dsi_panel_cfg *mi_cfg = &panel->mi_cfg;

	if (mi_get_panel_id(panel->mi_cfg.mi_panel_id) == L12_PANEL_PA  ||
			mi_get_panel_id(panel->mi_cfg.mi_panel_id) == L12_PANEL_PB ) {
		gray_scale_ptr = qcom_smem_get(QCOM_SMEM_HOST_ANY, SMEM_SW_DISPLAY_GRAY_SCALE_TABLE, &item_size);
		if (!IS_ERR(gray_scale_ptr) && item_size > 0) {
			DISP_INFO("gray scale data size %d\n", item_size);
			memcpy(mi_cfg->gray_scale_info, gray_scale_ptr, item_size);
			for (i = 1; i < item_size; i ++) {
				tmp = mi_cfg->gray_scale_info[i];
				DISP_INFO("index %d = 0x%02X\n", i, tmp);
			}
			mi_cfg->uefi_read_gray_scale_success = true;
		}
	}
}

static void mi_dsi_panel_parse_flat_config(struct dsi_panel *panel)
{
	struct dsi_parser_utils *utils = &panel->utils;
	struct mi_dsi_panel_cfg *mi_cfg = &panel->mi_cfg;

	mi_cfg->flat_sync_te = utils->read_bool(utils->data, "mi,flat-need-sync-te");
	if (mi_cfg->flat_sync_te)
		DISP_INFO("mi,flat-need-sync-te is defined\n");
	else
		DISP_DEBUG("mi,flat-need-sync-te is undefined\n");

#ifdef DISPLAY_FACTORY_BUILD
	mi_cfg->flat_sync_te = false;
#endif

	mi_cfg->flat_update_flag = utils->read_bool(utils->data, "mi,flat-update-flag");
	if (mi_cfg->flat_update_flag) {
		DISP_INFO("mi,flat-update-flag is defined\n");
	} else {
		DISP_DEBUG("mi,flat-update-flag is undefined\n");
	}

	mi_cfg->flat_update_gamma_zero = utils->read_bool(utils->data,
					"mi,flat-need-update-gamma-zero");
	if (mi_cfg->flat_update_gamma_zero) {
		DISP_INFO("mi,flat-need-update-gamma-zero is defined\n");
	} else {
		DISP_DEBUG("mi,flat-need-update-gamma-zero is undefined\n");
	}

	mi_cfg->flat_update_several_gamma = utils->read_bool(utils->data,
					"mi,flat-need-update-several-gamma");
	if (mi_cfg->flat_update_several_gamma)
		DISP_INFO("mi,flat-need-update-several-gamma is defined\n");
	else
		DISP_DEBUG("mi,flat-need-update-several-gamma is undefined\n");
}

static int mi_dsi_panel_parse_dc_config(struct dsi_panel *panel)
{
	int rc = 0;
	struct dsi_parser_utils *utils = &panel->utils;
	struct mi_dsi_panel_cfg *mi_cfg = &panel->mi_cfg;
	const char *string;

	mi_cfg->dc_feature_enable = utils->read_bool(utils->data, "mi,dc-feature-enabled");
	if (!mi_cfg->dc_feature_enable) {
		DISP_DEBUG("mi,dc-feature-enabled not defined\n");
		return rc;
	}
	DISP_INFO("mi,dc-feature-enabled is defined\n");

	rc = utils->read_string(utils->data, "mi,dc-feature-type", &string);
	if (rc){
		DISP_ERROR("mi,dc-feature-type not defined!\n");
		return -EINVAL;
	}
	if (!strcmp(string, "lut_compatible_backlight")) {
		mi_cfg->dc_type = TYPE_LUT_COMPATIBLE_BL;
	} else if (!strcmp(string, "crc_skip_backlight")) {
		mi_cfg->dc_type = TYPE_CRC_SKIP_BL;
	} else {
		DISP_ERROR("No valid mi,dc-feature-type string\n");
		return -EINVAL;
	}
	DISP_INFO("mi, dc type is %s\n", string);

	mi_cfg->dc_update_flag = utils->read_bool(utils->data, "mi,dc-update-flag");
	if (mi_cfg->dc_update_flag) {
		DISP_INFO("mi,dc-update-flag is defined\n");
	} else {
		DISP_DEBUG("mi,dc-update-flag not defined\n");
	}

	rc = utils->read_u32(utils->data, "mi,mdss-dsi-panel-dc-threshold", &mi_cfg->dc_threshold);
	if (rc) {
		mi_cfg->dc_threshold = 440;
		DISP_INFO("default dc threshold is %d\n", mi_cfg->dc_threshold);
	} else {
		DISP_INFO("dc threshold is %d \n", mi_cfg->dc_threshold);
	}

	return rc;
}

static int mi_dsi_panel_parse_backlight_config(struct dsi_panel *panel)
{
	int rc = 0;
#ifdef DISPLAY_FACTORY_BUILD
	u32 val = 0;
#endif
	struct dsi_parser_utils *utils = &panel->utils;
	struct mi_dsi_panel_cfg *mi_cfg = &panel->mi_cfg;

	mi_cfg->bl_wait_frame = false;
	mi_cfg->bl_enable = true;

	rc = utils->read_u32(utils->data, "mi,panel-on-dimming-delay", &mi_cfg->panel_on_dimming_delay);
	if (rc) {
		mi_cfg->panel_on_dimming_delay = 0;
		DISP_INFO("mi,panel-on-dimming-delay not specified\n");
	} else {
		DISP_INFO("mi,panel-on-dimming-delay is %d\n", mi_cfg->panel_on_dimming_delay);
	}

	mi_cfg->dimming_need_update_speed = utils->read_bool(utils->data,
					"mi,dimming-need-update-speed");
	if (mi_cfg->dimming_need_update_speed) {
		DISP_INFO("mi,dimming-need-update-speed is defined\n");
	} else {
		DISP_INFO("mi,dimming-need-update-speed is undefined\n");
	}

	rc = utils->read_u32_array(utils->data, "mi,dimming-node",
			mi_cfg->dimming_node, 5);
	if (rc) {
		DISP_INFO("mi,dimming-node is undefined\n");
	} else {
		DISP_INFO("mi,dimming-node is %d,%d,%d,%d,%d\n", mi_cfg->dimming_node[0],
				mi_cfg->dimming_node[1], mi_cfg->dimming_node[2],
				mi_cfg->dimming_node[3], mi_cfg->dimming_node[4]);
	}

	rc = utils->read_u32(utils->data, "mi,doze-hbm-dbv-level", &mi_cfg->doze_hbm_dbv_level);
	if (rc) {
		mi_cfg->doze_hbm_dbv_level = 0;
		DISP_INFO("mi,doze-hbm-dbv-level not specified\n");
	} else {
		DISP_INFO("mi,doze-hbm-dbv-level is %d\n", mi_cfg->doze_hbm_dbv_level);
	}

	rc = utils->read_u32(utils->data, "mi,doze-lbm-dbv-level", &mi_cfg->doze_lbm_dbv_level);
	if (rc) {
		mi_cfg->doze_lbm_dbv_level = 0;
		DISP_INFO("mi,doze-lbm-dbv-level not specified\n");
	} else {
		DISP_INFO("mi,doze-lbm-dbv-level is %d\n", mi_cfg->doze_lbm_dbv_level);
	}

	rc = utils->read_u32(utils->data, "mi,max-brightness-clone", &mi_cfg->max_brightness_clone);
	if (rc) {
		mi_cfg->max_brightness_clone = DEFAULT_MAX_BRIGHTNESS_CLONE;
	}
	DISP_INFO("max_brightness_clone=%d\n", mi_cfg->max_brightness_clone);

	rc = utils->read_u32(utils->data, "mi,normal-max-brightness-clone", &mi_cfg->normal_max_brightness_clone);
	if (rc) {
		mi_cfg->normal_max_brightness_clone = DEFAULT_MAX_BRIGHTNESS_CLONE;
	}
	DISP_INFO("normal_max_brightness_clone=%d\n", mi_cfg->normal_max_brightness_clone);

	mi_cfg->thermal_dimming_enabled = utils->read_bool(utils->data, "mi,thermal-dimming-flag");
	if (mi_cfg->thermal_dimming_enabled) {
		DISP_INFO("thermal_dimming enabled\n");
	}

	mi_cfg->video_fps_cmdsets_enanle = utils->read_bool(utils->data, "mi,video-fps-cmdsets-flag");
	if (mi_cfg->video_fps_cmdsets_enanle) {
		DISP_INFO("video_fps_cmdsets enabled\n");
	}

#ifdef DISPLAY_FACTORY_BUILD
	rc = utils->read_u32(utils->data, "mi,mdss-dsi-fac-bl-max-level", &val);
	if (rc) {
		rc = 0;
		DISP_DEBUG("[%s] factory bl-max-level unspecified\n", panel->name);
	} else {
		panel->bl_config.bl_max_level = val;
	}

	rc = utils->read_u32(utils->data, "mi,mdss-fac-brightness-max-level",&val);
	if (rc) {
		rc = 0;
		DISP_DEBUG("[%s] factory brigheness-max-level unspecified\n", panel->name);
	} else {
		panel->bl_config.brightness_max_level = val;
	}
	DISP_INFO("bl_max_level is %d, brightness_max_level is %d\n",
		panel->bl_config.bl_max_level, panel->bl_config.brightness_max_level);
#endif

	return rc;
}

int mi_dsi_panel_parse_config(struct dsi_panel *panel)
{
	int rc = 0;
	struct dsi_parser_utils *utils = &panel->utils;
	struct mi_dsi_panel_cfg *mi_cfg = &panel->mi_cfg;

	rc = utils->read_u64(utils->data, "mi,panel-id", &mi_cfg->mi_panel_id);
	if (rc) {
		mi_cfg->mi_panel_id = 0;
		DISP_INFO("mi,panel-id not specified\n");
	} else {
		DISP_INFO("mi,panel-id is 0x%llx (%s)\n",
			mi_cfg->mi_panel_id, mi_get_panel_id_name(mi_cfg->mi_panel_id));
	}

	mi_cfg->panel_build_id_read_needed =
		utils->read_bool(utils->data, "mi,panel-build-id-read-needed");
	if (mi_cfg->panel_build_id_read_needed) {
		rc = mi_dsi_panel_parse_build_id_read_config(panel);
		if (rc) {
			mi_cfg->panel_build_id_read_needed = false;
			DSI_ERR("[%s] failed to get panel build id read infos, rc=%d\n",
				panel->name, rc);
		}
	}
	mi_cfg->flatmode_check_enabled =
		utils->read_bool(utils->data, "mi,flatmode-status-check-enabled");
	if (mi_cfg->flatmode_check_enabled)
		DISP_INFO("flatmode_check_enabled is defined\n");
	else
		DISP_INFO("flatmode_check_enabled is undefined\n");

	mi_cfg->is_tddi_flag = false;
	mi_cfg->panel_dead_flag = false;
	mi_cfg->tddi_doubleclick_flag = false;
	mi_cfg->is_tddi_flag = utils->read_bool(utils->data, "mi,is-tddi-flag");
	if (mi_cfg->is_tddi_flag)
		pr_info("panel is tddi\n");

	rc = dsi_panel_parse_cell_id_read_config(panel);
	if (rc) {
		DSI_ERR("[%s] failed to get panel cell id read infos, rc=%d\n",
			panel->name, rc);
		rc = 0;
	}
	rc = dsi_panel_parse_wp_reg_read_config(panel);
	if (rc) {
		DSI_ERR("[%s] failed to get panel wp read infos, rc=%d\n",
			panel->name, rc);
		rc = 0;
	}

	mi_dsi_panel_parse_round_corner_config(panel);
	mi_dsi_panel_parse_lhbm_config(panel);
	mi_dsi_panel_parse_lockdown_config(panel);
	mi_dsi_panel_parse_gray_scale_config(panel);
	mi_dsi_panel_parse_flat_config(panel);
	rc |= mi_dsi_panel_parse_dc_config(panel);
	rc |= mi_dsi_panel_parse_backlight_config(panel);

	rc = utils->read_u32(utils->data, "mi,panel-hbm-backlight-threshold", &mi_cfg->hbm_backlight_threshold);
	if (rc)
		mi_cfg->hbm_backlight_threshold = 8192;
	DISP_INFO("panel hbm backlight threshold %d\n", mi_cfg->hbm_backlight_threshold);

	mi_cfg->count_hbm_by_backlight = utils->read_bool(utils->data, "mi,panel-count-hbm-by-backlight-flag");
	if (mi_cfg->count_hbm_by_backlight)
		DISP_INFO("panel count hbm by backlight\n");

	mi_cfg->ignore_esd_in_aod = utils->read_bool(utils->data, "mi,panel-ignore-esd-in-aod");
	if (mi_cfg->ignore_esd_in_aod)
		DISP_INFO("panel don't recovery in aod\n");

	return rc;
}

