/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#ifndef _CAM_LX7_CORE_H_
#define _CAM_LX7_CORE_H_

#include "cam_hw_intf.h"
#include "cam_icp_hw_intf.h"

#define LX7_CSR_BASE  0
#define LX7_CIRQ_BASE 1

/* TODO: Update once we're ready to use TZ */
#define UNSUPPORTED_PROC_PAS_ID   30
#define CAM_FW_PAS_ID             UNSUPPORTED_PROC_PAS_ID

struct cam_lx7_core_info {
	struct cam_icp_irq_cb irq_cb;
	uint32_t cpas_handle;
	bool cpas_start;
};

int cam_lx7_hw_init(void *priv, void *args, uint32_t arg_size);
int cam_lx7_hw_deinit(void *priv, void *args, uint32_t arg_size);
int cam_lx7_process_cmd(void *priv, uint32_t cmd_type,
			void *args, uint32_t arg_size);

int cam_lx7_cpas_register(struct cam_hw_intf *lx7_intf);
int cam_lx7_cpas_unregister(struct cam_hw_intf *lx7_intf);

irqreturn_t cam_lx7_handle_irq(int irq_num, void *data);

void cam_lx7_irq_raise(void *priv);
void cam_lx7_irq_enable(void *priv);
void __iomem *cam_lx7_iface_addr(void *priv);

#endif /* _CAM_LX7_CORE_H_ */
