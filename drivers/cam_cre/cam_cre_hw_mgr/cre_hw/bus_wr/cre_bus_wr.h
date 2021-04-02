/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#ifndef CRE_BUS_WR_H
#define CRE_BUS_WR_H

#include <linux/types.h>
#include <linux/completion.h>
#include <media/cam_cre.h>
#include "cre_hw.h"
#include "cam_hw_mgr_intf.h"
#include "cam_hw_intf.h"
#include "cam_soc_util.h"
#include "cam_cre_hw_mgr.h"

/**
 * struct cre_bus_wr_io_port_info
 *
 * @num_frames_cmds: Number of frame commands
 * @go_cmd_addr:     GO command address
 * @go_cmd_len:      GO command length
 */
struct cre_bus_wr_io_port_info {
	uint32_t  num_frames_cmds;
	uint32_t *go_cmd_addr;
	uint32_t  go_cmd_len;
	uint32_t  output_port_id[CRE_MAX_OUT_RES];
	uint32_t  output_format_type[CRE_MAX_OUT_RES];
};

/**
 * struct cre_bus_wr_io_port_batch
 *
 * num_batch:   Number of batches
 * io_port: CDM IO Port Info
 */
struct cre_bus_wr_io_port_batch {
	uint32_t num_batch;
	struct cre_bus_wr_io_port_info io_port[CRE_MAX_BATCH_SIZE];
};

/**
 * struct cre_bus_wr_wm
 *
 * @wm_port_id:  WM port ID
 * @format_type: Format type
 */
struct cre_bus_wr_wm {
	uint32_t wm_port_id;
	uint32_t format_type;
};

/**
 * struct cre_bus_out_port_to_wm
 *
 * @output_port_id: Output port ID
 * @num_combos:     Number of combos
 * @num_wm:         Number of WMs
 * @wm_port_id:     WM port Id
 */
struct cre_bus_out_port_to_wm {
	uint32_t output_port_id;
	uint32_t num_wm;
	uint32_t wm_port_id[CRE_MAX_OUT_RES];
};

/**
 * struct cre_bus_wr_ctx
 *
 * @cre_acquire:       CRE acquire structure
 * @security_flag:     security flag
 * @num_out_ports:     Number of out ports
 * @io_port_info:      IO port info
 */
struct cre_bus_wr_ctx {
	struct cam_cre_acquire_dev_info *cre_acquire;
	bool security_flag;
	uint32_t num_out_ports;
	struct cre_bus_wr_io_port_info io_port_info;
	struct cre_bus_wr_io_port_batch io_port_batch;
};

/**
 * struct cre_bus_wr
 *
 * @cre_hw_info:    CRE hardware info
 * @out_port_to_wm: IO port to WM mapping
 * @bus_wr_ctx:     WM context
 */
struct cre_bus_wr {
	struct cam_cre_hw *cre_hw_info;
	struct cre_bus_out_port_to_wm out_port_to_wm[CRE_MAX_OUT_RES];
	struct cre_bus_wr_ctx *bus_wr_ctx[CRE_CTX_MAX];
};

#endif /* CRE_BUS_WR_H */
