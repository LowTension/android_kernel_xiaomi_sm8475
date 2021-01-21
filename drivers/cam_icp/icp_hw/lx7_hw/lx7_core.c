// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#include <linux/firmware.h>
#include <linux/of_address.h>
#include <linux/qcom_scm.h>

#include "cam_cpas_api.h"
#include "cam_debug_util.h"
#include "cam_hw.h"
#include "cam_hw_intf.h"
#include "cam_icp_hw_mgr_intf.h"
#include "cam_icp_hw_intf.h"
#include "hfi_intf.h"
#include "lx7_core.h"
#include "lx7_reg.h"
#include "lx7_soc.h"

#define TZ_STATE_RESUME  0
#define TZ_STATE_SUSPEND 1

#define LX7_FW_NAME "CAMERA_ICP.elf"

#define LX7_GEN_PURPOSE_REG_OFFSET 0x20

static int cam_lx7_ubwc_configure(struct cam_hw_soc_info *soc_info)
{
	int i = 0, rc, ddr_type;
	struct lx7_soc_info *soc_priv;
	uint32_t ipe_ubwc_cfg[UBWC_CONFIG_MAX];
	uint32_t bps_ubwc_cfg[UBWC_CONFIG_MAX];

	if (!soc_info || !soc_info->soc_private) {
		CAM_ERR(CAM_ICP, "invalid LX7 soc info");
		return -EINVAL;
	}

	soc_priv = soc_info->soc_private;

	ddr_type = of_fdt_get_ddrtype();
	if (ddr_type == DDR_TYPE_LPDDR5 || ddr_type == DDR_TYPE_LPDDR5X)
		i = 1;

	ipe_ubwc_cfg[0] = soc_priv->ubwc_cfg.ipe_fetch[i];
	ipe_ubwc_cfg[1] = soc_priv->ubwc_cfg.ipe_write[i];

	bps_ubwc_cfg[0] = soc_priv->ubwc_cfg.bps_fetch[i];
	bps_ubwc_cfg[1] = soc_priv->ubwc_cfg.bps_write[i];

	rc = hfi_cmd_ubwc_config_ext(ipe_ubwc_cfg, bps_ubwc_cfg);
	if (rc)	{
		CAM_ERR(CAM_ICP, "failed to write UBWC config rc=%d", rc);
		return rc;
	}

	return 0;
}

static int cam_lx7_cpas_vote(struct cam_lx7_core_info *core_info,
			struct cam_icp_cpas_vote *vote)
{
	int rc;

	if (!core_info || !vote)
		return -EINVAL;

	if (vote->ahb_vote_valid) {
		rc = cam_cpas_update_ahb_vote(core_info->cpas_handle,
					&vote->ahb_vote);
		if (rc) {
			CAM_ERR(CAM_ICP, "AHB vote update failed rc=%d", rc);
			return rc;
		}
	}

	if (vote->axi_vote_valid) {
		rc = cam_cpas_update_axi_vote(core_info->cpas_handle,
					&vote->axi_vote);
		if (rc) {
			CAM_ERR(CAM_ICP, "AXI vote update failed rc=%d", rc);
			return rc;
		}
	}

	return 0;
}

static bool cam_lx7_cpas_cb(uint32_t handle, void *user_data,
			struct cam_cpas_irq_data *irq_data)
{
	bool ret = false;
	(void)user_data;

	if (!irq_data)
		return false;

	switch (irq_data->irq_type) {
	case CAM_CAMNOC_IRQ_IPE_BPS_UBWC_DECODE_ERROR:
		CAM_ERR_RATE_LIMIT(CAM_ICP,
				"IPE/BPS UBWC decode error status=0x%08x",
				irq_data->u.dec_err.decerr_status.value);
		ret = true;
	case CAM_CAMNOC_IRQ_IPE_BPS_UBWC_ENCODE_ERROR:
		CAM_ERR_RATE_LIMIT(CAM_ICP,
				"IPE/BPS UBWC encode error status=0x%08x",
				irq_data->u.enc_err.encerr_status.value);
		ret = true;
	default:
		CAM_ERR(CAM_ICP, "unhandled irq_type=%d", irq_data->irq_type);
		break;
	}

	return ret;
}

int cam_lx7_cpas_register(struct cam_hw_intf *lx7_intf)
{
	struct cam_cpas_register_params params;
	struct cam_hw_info *lx7_info;
	struct cam_lx7_core_info *core_info;
	int rc;

	if (!lx7_intf)
		return -EINVAL;

	lx7_info = lx7_intf->hw_priv;

	params.dev = lx7_info->soc_info.dev;
	params.cell_index = lx7_intf->hw_idx;
	params.cam_cpas_client_cb = cam_lx7_cpas_cb;
	params.userdata = NULL;

	strlcpy(params.identifier, "icp", CAM_HW_IDENTIFIER_LENGTH);

	rc = cam_cpas_register_client(&params);
	if (rc)
		return rc;

	core_info = lx7_info->core_info;
	core_info->cpas_handle = params.client_handle;

	return rc;
}

int cam_lx7_cpas_unregister(struct cam_hw_intf *lx7_intf)
{
	struct cam_hw_info *lx7_info;
	struct cam_lx7_core_info *core_info;

	if (!lx7_intf)
		return -EINVAL;

	lx7_info = lx7_intf->hw_priv;
	core_info = lx7_info->core_info;

	return cam_cpas_unregister_client(core_info->cpas_handle);
}

static int __lx7_cpas_start(struct cam_lx7_core_info *core_info,
			struct cam_icp_cpas_vote *vote)
{
	int rc;

	if (!core_info || core_info->cpas_start)
		return -EINVAL;

	rc = cam_cpas_start(core_info->cpas_handle,
			&vote->ahb_vote, &vote->axi_vote);
	if (rc) {
		CAM_ERR(CAM_ICP, "failed to start cpas rc=%d", rc);
		return rc;
	}

	core_info->cpas_start = true;

	return 0;
}

static int cam_lx7_cpas_start(struct cam_lx7_core_info *core_info)
{
	struct cam_icp_cpas_vote vote;

	vote.ahb_vote.type = CAM_VOTE_ABSOLUTE;
	vote.ahb_vote.vote.level = CAM_LOWSVS_VOTE;
	vote.axi_vote.num_paths = 1;

	vote.axi_vote.axi_path[0].path_data_type = CAM_ICP_DEFAULT_AXI_PATH;
	vote.axi_vote.axi_path[0].transac_type = CAM_ICP_DEFAULT_AXI_TRANSAC;
	vote.axi_vote.axi_path[0].camnoc_bw = CAM_ICP_BW_BYTES_VOTE;
	vote.axi_vote.axi_path[0].mnoc_ab_bw = CAM_ICP_BW_BYTES_VOTE;
	vote.axi_vote.axi_path[0].mnoc_ib_bw = CAM_ICP_BW_BYTES_VOTE;
	vote.axi_vote.axi_path[0].ddr_ab_bw = CAM_ICP_BW_BYTES_VOTE;
	vote.axi_vote.axi_path[0].ddr_ib_bw = CAM_ICP_BW_BYTES_VOTE;

	return __lx7_cpas_start(core_info, &vote);
}

static int cam_lx7_cpas_stop(struct cam_lx7_core_info *core_info)
{
	int rc;

	if (!core_info || !core_info->cpas_start)
		return -EINVAL;

	rc = cam_cpas_stop(core_info->cpas_handle);
	if (rc) {
		CAM_ERR(CAM_ICP, "failed to stop cpas rc=%d", rc);
		return rc;
	}

	core_info->cpas_start = false;

	return 0;
}

int cam_lx7_hw_init(void *priv, void *args, uint32_t arg_size)
{
	struct cam_hw_info *lx7 = priv;
	int rc;

	if (!lx7) {
		CAM_ERR(CAM_ICP, "LX7 device info cannot be NULL");
		return -EINVAL;
	}

	rc = cam_lx7_cpas_start(lx7->core_info);
	if (rc)
		return rc;

	rc = cam_lx7_soc_resources_enable(&lx7->soc_info);
	if (rc) {
		CAM_ERR(CAM_ICP, "failed to enable soc resources rc=%d", rc);
		goto soc_fail;
	}

	return 0;

soc_fail:
	cam_lx7_cpas_stop(lx7->core_info);
	return rc;
}

int cam_lx7_hw_deinit(void *priv, void *args, uint32_t arg_size)
{
	struct cam_hw_info *lx7_info = priv;
	int rc;

	if (!lx7_info) {
		CAM_ERR(CAM_ICP, "LX7 device info cannot be NULL");
		return -EINVAL;
	}

	rc = cam_lx7_soc_resources_disable(&lx7_info->soc_info);
	if (rc) {
		CAM_ERR(CAM_ICP, "failed to disable soc resources rc=%d", rc);
		return rc;
	}

	return cam_lx7_cpas_stop(lx7_info->core_info);
}

static int __tz_set_icp_state(uint32_t state)
{
	int rc;

	rc = qcom_scm_set_remote_state(state, CAM_FW_PAS_ID);
	if (rc)
		CAM_ERR(CAM_ICP, "remote state set to %s failed rc=%d",
			state == TZ_STATE_RESUME ? "resume" : "suspend", rc);

	return rc;
}

int cam_lx7_process_cmd(void *priv, uint32_t cmd_type,
			void *args, uint32_t arg_size)
{
	struct cam_hw_info *lx7_info = priv;
	int rc = -EINVAL;

	if (!lx7_info) {
		CAM_ERR(CAM_ICP, "LX7 device info cannot be NULL");
		return -EINVAL;
	}

	switch (cmd_type) {
	case CAM_ICP_CMD_POWER_COLLAPSE:
		rc = __tz_set_icp_state(TZ_STATE_SUSPEND);
		break;
	case CAM_ICP_CMD_POWER_RESUME:
		rc = __tz_set_icp_state(TZ_STATE_RESUME);
		break;
	case CAM_ICP_CMD_VOTE_CPAS:
		rc = cam_lx7_cpas_vote(lx7_info->core_info, args);
		break;
	case CAM_ICP_CMD_CPAS_START:
		rc = __lx7_cpas_start(lx7_info->core_info, args);
		break;
	case CAM_ICP_CMD_CPAS_STOP:
		rc = cam_lx7_cpas_stop(lx7_info->core_info);
		break;
	case CAM_ICP_CMD_UBWC_CFG:
		rc = cam_lx7_ubwc_configure(&lx7_info->soc_info);
		break;
	default:
		CAM_ERR(CAM_ICP, "invalid command type=%u", cmd_type);
		break;
	}

	return rc;
}

irqreturn_t cam_lx7_handle_irq(int irq_num, void *data)
{
	struct cam_hw_info *lx7_info = data;
	struct cam_lx7_core_info *core_info = NULL;
	bool recover = false;
	uint32_t status = 0;
	void __iomem *cirq_base;

	if (!lx7_info) {
		CAM_ERR(CAM_ICP, "invalid LX7 device info");
		return IRQ_NONE;
	}

	cirq_base = lx7_info->soc_info.reg_map[LX7_CIRQ_BASE].mem_base;

	status = cam_io_r_mb(cirq_base + ICP_LX7_CIRQ_OB_STATUS);

	cam_io_w_mb(status, cirq_base + ICP_LX7_CIRQ_OB_CLEAR);
	cam_io_w_mb(LX7_IRQ_CLEAR_CMD, cirq_base + ICP_LX7_CIRQ_OB_IRQ_CMD);

	if (status & (LX7_WDT_BITE_WS0 | LX7_WDT_BITE_WS1)) {
		CAM_ERR_RATE_LIMIT(CAM_ICP, "got watchdog interrupt from LX7");
		recover = true;
	}

	core_info = lx7_info->core_info;

	spin_lock(&lx7_info->hw_lock);
	if (core_info->irq_cb.cb)
		core_info->irq_cb.cb(core_info->irq_cb.data,
						recover);
	spin_unlock(&lx7_info->hw_lock);

	return IRQ_HANDLED;
}

void cam_lx7_irq_raise(void *priv)
{
	struct cam_hw_info *lx7_info = priv;

	if (!lx7_info) {
		CAM_ERR(CAM_ICP, "invalid LX7 device info");
		return;
	}

	cam_io_w_mb(LX7_HOST2ICPINT,
		lx7_info->soc_info.reg_map[LX7_CIRQ_BASE].mem_base +
		ICP_LX7_CIRQ_HOST2ICPINT);
}

void cam_lx7_irq_enable(void *priv)
{
	struct cam_hw_info *lx7_info = priv;

	if (!lx7_info) {
		CAM_ERR(CAM_ICP, "invalid LX7 device info");
		return;
	}

	cam_io_w_mb(LX7_WDT_BITE_WS0 | LX7_ICP2HOSTINT,
		lx7_info->soc_info.reg_map[LX7_CIRQ_BASE].mem_base +
		ICP_LX7_CIRQ_OB_MASK);
}

void __iomem *cam_lx7_iface_addr(void *priv)
{
	struct cam_hw_info *lx7_info = priv;
	void __iomem *base;

	if (!lx7_info) {
		CAM_ERR(CAM_ICP, "invalid LX7 device info");
		return ERR_PTR(-EINVAL);
	}

	base = lx7_info->soc_info.reg_map[LX7_CSR_BASE].mem_base;

	return base + LX7_GEN_PURPOSE_REG_OFFSET;
}
