// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#include <linux/of.h>
#include <linux/debugfs.h>
#include <linux/videodev2.h>
#include <linux/uaccess.h>
#include <linux/platform_device.h>
#include <linux/firmware.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/iopoll.h>
#include <media/cam_cre.h>
#include "cam_io_util.h"
#include "cam_hw.h"
#include "cam_hw_intf.h"
#include "cre_core.h"
#include "cre_soc.h"
#include "cam_soc_util.h"
#include "cam_io_util.h"
#include "cam_cpas_api.h"
#include "cam_debug_util.h"
#include "cre_hw.h"
#include "cre_dev_intf.h"
#include "cre_bus_wr.h"

static struct cre_bus_wr *wr_info;

#define update_cre_reg_set(cre_reg_buf, off, val) \
	do {                                           \
		cre_reg_buf->wr_reg_set[cre_reg_buf->num_wr_reg_set].offset = (off); \
		cre_reg_buf->wr_reg_set[cre_reg_buf->num_wr_reg_set].value = (val); \
		cre_reg_buf->num_wr_reg_set++; \
	} while (0)

static int cam_cre_bus_en_port_idx(
	struct cam_cre_request *cre_request,
	uint32_t batch_idx,
	uint32_t output_port_id)
{
	int i;
	struct cre_io_buf *io_buf;

	if (batch_idx >= CRE_MAX_BATCH_SIZE) {
		CAM_ERR(CAM_CRE, "Invalid batch idx: %d", batch_idx);
		return -EINVAL;
	}

	for (i = 0; i < cre_request->num_io_bufs[batch_idx]; i++) {
		io_buf = cre_request->io_buf[batch_idx][i];
		if (io_buf->direction != CAM_BUF_OUTPUT)
			continue;
		if (io_buf->resource_type == output_port_id)
			return i;
	}

	return -EINVAL;
}

static int cam_cre_bus_wr_out_port_idx(uint32_t output_port_id)
{
	int i;

	for (i = 0; i < CRE_MAX_OUT_RES; i++)
		if (wr_info->out_port_to_wm[i].output_port_id == output_port_id)
			return i;

	return -EINVAL;
}

static int cam_cre_bus_wr_reg_set_update(struct cam_cre_hw *cam_cre_hw_info,
	int32_t ctx_id, void *data)
{
	int i;
	uint32_t num_reg_set;
	struct cre_reg_set *wr_reg_set;
	struct cam_cre_dev_reg_set_update *reg_set_upd_cmd =
		(struct cam_cre_dev_reg_set_update *)data;

	num_reg_set = reg_set_upd_cmd->cre_reg_buf.num_wr_reg_set;
	wr_reg_set = reg_set_upd_cmd->cre_reg_buf.wr_reg_set;

	for (i = 0; i < num_reg_set; i++) {
		cam_io_w_mb(wr_reg_set[i].value,
			cam_cre_hw_info->bus_wr_reg_offset->base + wr_reg_set[i].offset);
	}
	return 0;
}

static int cam_cre_bus_wr_release(struct cam_cre_hw *cam_cre_hw_info,
	int32_t ctx_id, void *data)
{
	if (ctx_id < 0 || ctx_id >= CRE_CTX_MAX) {
		CAM_ERR(CAM_CRE, "Invalid data: %d", ctx_id);
		return -EINVAL;
	}

	vfree(wr_info->bus_wr_ctx[ctx_id]);
	wr_info->bus_wr_ctx[ctx_id] = NULL;

	return 0;
}

static uint32_t *cam_cre_bus_wr_update(struct cam_cre_hw *cam_cre_hw_info,
	int32_t ctx_id, struct cam_cre_dev_prepare_req *prepare,
	int batch_idx, int io_idx,
	struct cre_reg_buffer *cre_reg_buf)
{
	int k, out_port_idx;
	uint32_t num_wm_ports;
	uint32_t comb_idx = 0;
	uint32_t req_idx;
	uint32_t temp = 0;
	uint32_t wm_port_id;
	struct cam_hw_prepare_update_args *prepare_args;
	struct cam_cre_ctx *ctx_data;
	struct cam_cre_request *cre_request;
	struct cre_io_buf *io_buf;
	struct cre_bus_wr_ctx *bus_wr_ctx;
	struct cam_cre_bus_wr_reg *wr_reg;
	struct cam_cre_bus_wr_client_reg *wr_reg_client;
	struct cam_cre_bus_wr_reg_val *wr_reg_val;
	struct cam_cre_bus_wr_client_reg_val *wr_res_val_client;
	struct cre_bus_out_port_to_wm *out_port_to_wm;

	if (ctx_id < 0 || !prepare) {
		CAM_ERR(CAM_CRE, "Invalid data: %d %x", ctx_id, prepare);
		return NULL;
	}

	if (batch_idx >= CRE_MAX_BATCH_SIZE) {
		CAM_ERR(CAM_CRE, "Invalid batch idx: %d", batch_idx);
		return NULL;
	}

	if (io_idx >= CRE_MAX_IO_BUFS) {
		CAM_ERR(CAM_CRE, "Invalid IO idx: %d", io_idx);
		return NULL;
	}

	prepare_args = prepare->prepare_args;
	ctx_data = prepare->ctx_data;
	req_idx = prepare->req_idx;

	cre_request = ctx_data->req_list[req_idx];
	bus_wr_ctx = wr_info->bus_wr_ctx[ctx_id];
	wr_reg = cam_cre_hw_info->bus_wr_reg_offset;
	wr_reg_val = cam_cre_hw_info->bus_wr_reg_val;

	CAM_DBG(CAM_CRE, "req_idx = %d req_id = %lld offset = %d",
		req_idx, cre_request->request_id);

	io_buf = cre_request->io_buf[batch_idx][io_idx];
	CAM_DBG(CAM_CRE, "batch = %d io buf num = %d dir = %d rsc %d",
		batch_idx, io_idx, io_buf->direction, io_buf->resource_type);

	out_port_idx =
		cam_cre_bus_wr_out_port_idx(io_buf->resource_type);
	if (out_port_idx < 0) {
		CAM_ERR(CAM_CRE, "Invalid idx for rsc type: %d",
			io_buf->resource_type);
		return NULL;
	}
	out_port_to_wm = &wr_info->out_port_to_wm[out_port_idx];
	num_wm_ports = out_port_to_wm->num_wm;

	for (k = 0; k < io_buf->num_planes; k++) {
		CAM_DBG(CAM_CRE, "comb_idx = %d p_idx = %d",
			comb_idx, k);
		/* frame level info */
		wm_port_id = out_port_to_wm->wm_port_id[k];
		wr_reg_client = &wr_reg->wr_clients[wm_port_id];
		wr_res_val_client = &wr_reg_val->wr_clients[wm_port_id];

		/* Core cfg: enable, Mode */
		temp = 0;
		temp |= ((wr_res_val_client->mode &
			wr_res_val_client->mode_mask) <<
			wr_res_val_client->mode_shift);
		update_cre_reg_set(cre_reg_buf,
			wr_reg->offset + wr_reg_client->client_cfg,
			temp);

		/* Address of the Image */
		update_cre_reg_set(cre_reg_buf,
			wr_reg->offset + wr_reg_client->img_addr,
			io_buf->p_info[k].iova_addr);

		/* Buffer size */
		temp = 0;
		temp = io_buf->p_info[k].width;
		temp |= (io_buf->p_info[k].height &
				wr_res_val_client->height_mask) <<
				wr_res_val_client->height_shift;
		update_cre_reg_set(cre_reg_buf,
			wr_reg->offset + wr_reg_client->img_cfg_0,
			temp);

		update_cre_reg_set(cre_reg_buf,
			wr_reg->offset + wr_reg_client->img_cfg_1,
			io_buf->p_info[k].x_init);

		/* stride */
		update_cre_reg_set(cre_reg_buf,
			wr_reg->offset + wr_reg_client->img_cfg_2,
			io_buf->p_info[k].stride);

		/* pack cfg : Format and alignment */
		temp = 0;
		temp |= ((io_buf->p_info[k].format &
			wr_res_val_client->format_mask) <<
			wr_res_val_client->format_shift);
		temp |= ((io_buf->p_info[k].alignment &
			wr_res_val_client->alignment_mask) <<
			wr_res_val_client->alignment_shift);
		update_cre_reg_set(cre_reg_buf,
			wr_reg->offset + wr_reg_client->packer_cfg,
			temp);
		/* Upadte debug status CFG*/
		temp = 0xFFFF;
		update_cre_reg_set(cre_reg_buf,
			wr_reg->offset + wr_reg_client->debug_status_cfg,
			temp);
	}

	return (uint32_t *)cre_reg_buf;
}

static uint32_t *cam_cre_bus_wm_disable(struct cam_cre_hw *cam_cre_hw_info,
	int32_t ctx_id, struct cam_cre_dev_prepare_req *prepare,
	int batch_idx, int io_idx,
	struct cre_reg_buffer *cre_reg_buf)
{
	int k;
	uint32_t num_wm_ports;
	uint32_t req_idx;
	uint32_t wm_port_id;
	struct cam_cre_ctx *ctx_data;
	struct cre_bus_wr_ctx *bus_wr_ctx;
	struct cam_cre_bus_wr_reg *wr_reg;
	struct cre_bus_out_port_to_wm *out_port_to_wm;
	struct cam_cre_bus_wr_client_reg *wr_reg_client;


	if (ctx_id < 0 || !prepare) {
		CAM_ERR(CAM_CRE, "Invalid data: %d %x", ctx_id, prepare);
		return NULL;
	}

	if (batch_idx >= CRE_MAX_BATCH_SIZE) {
		CAM_ERR(CAM_CRE, "Invalid batch idx: %d", batch_idx);
		return NULL;
	}

	ctx_data = prepare->ctx_data;
	req_idx = prepare->req_idx;

	bus_wr_ctx = wr_info->bus_wr_ctx[ctx_id];
	wr_reg = cam_cre_hw_info->bus_wr_reg_offset;

	CAM_DBG(CAM_CRE,
		"req_idx = %d out_idx %d b %d",
		req_idx, io_idx, batch_idx);

	out_port_to_wm = &wr_info->out_port_to_wm[io_idx];
	num_wm_ports = out_port_to_wm->num_wm;

	for (k = 0; k < num_wm_ports; k++) {
		/* frame level info */
		wm_port_id = out_port_to_wm->wm_port_id[k];
		wr_reg_client = &wr_reg->wr_clients[wm_port_id];

		/* Core cfg: enable, Mode */
		update_cre_reg_set(cre_reg_buf,
			wr_reg->offset + wr_reg_client->client_cfg,
			0);
	}

	return (uint32_t *)cre_reg_buf;
}

static int cam_cre_bus_wr_prepare(struct cam_cre_hw *cam_cre_hw_info,
	int32_t ctx_id, void *data)
{
	int rc = 0;
	int i, j = 0;
	uint32_t req_idx;
	struct cam_cre_dev_prepare_req *prepare;
	struct cam_cre_ctx *ctx_data;
	struct cam_cre_request *cre_request;
	struct cre_io_buf *io_buf;
	int io_buf_idx;
	struct cre_bus_wr_ctx *bus_wr_ctx;
	struct cre_reg_buffer *cre_reg_buf;
	uint32_t *ret;

	if (ctx_id < 0 || !data) {
		CAM_ERR(CAM_CRE, "Invalid data: %d %x", ctx_id, data);
		return -EINVAL;
	}
	prepare = data;
	ctx_data = prepare->ctx_data;
	req_idx = prepare->req_idx;
	bus_wr_ctx = wr_info->bus_wr_ctx[ctx_id];

	cre_request = ctx_data->req_list[req_idx];
	cre_reg_buf = &cre_request->cre_reg_buf;

	CAM_DBG(CAM_CRE, "req_idx = %d req_id = %lld offset = %d",
		req_idx, cre_request->request_id);


	for (i = 0; i < cre_request->num_batch; i++) {
		for (j = 0; j < cre_request->num_io_bufs[i]; j++) {
			io_buf = cre_request->io_buf[i][j];
			CAM_DBG(CAM_CRE, "batch = %d io buf num = %d dir = %d",
				i, j, io_buf->direction);
			if (io_buf->direction != CAM_BUF_OUTPUT)
				continue;

			ret = cam_cre_bus_wr_update(cam_cre_hw_info,
				ctx_id, prepare, i, j,
				cre_reg_buf);
			if (!ret) {
				rc = -EINVAL;
				goto end;
			}
		}
	}

	/* Disable WMs which are not enabled */
	for (i = 0; i < cre_request->num_batch; i++) {
		for (j = CRE_MAX_IN_RES; j <= CRE_MAX_OUT_RES; j++) {
			io_buf_idx = cam_cre_bus_en_port_idx(cre_request, i, j);
			if (io_buf_idx >= 0)
				continue;

			io_buf_idx = cam_cre_bus_wr_out_port_idx(j);
			if (io_buf_idx < 0) {
				CAM_ERR(CAM_CRE, "Invalid idx for rsc type:%d",
					j);
				return io_buf_idx;
			}
			ret = cam_cre_bus_wm_disable(cam_cre_hw_info,
				ctx_id, prepare, i, io_buf_idx,
				cre_reg_buf);
			if (!ret) {
				rc = -EINVAL;
				goto end;
			}
		}
	}

end:
	return rc;
}

static int cam_cre_bus_wr_acquire(struct cam_cre_hw *cam_cre_hw_info,
	int32_t ctx_id, void *data)
{
	int rc = 0, i;
	struct cam_cre_acquire_dev_info *in_acquire;
	struct cre_bus_wr_ctx *bus_wr_ctx;
	struct cre_bus_out_port_to_wm *out_port_to_wr;
	int out_port_idx;

	if (ctx_id < 0 || !data || ctx_id >= CRE_CTX_MAX) {
		CAM_ERR(CAM_CRE, "Invalid data: %d %x", ctx_id, data);
		return -EINVAL;
	}

	wr_info->bus_wr_ctx[ctx_id] = vzalloc(sizeof(struct cre_bus_wr_ctx));
	if (!wr_info->bus_wr_ctx[ctx_id]) {
		CAM_ERR(CAM_CRE, "Out of memory");
		return -ENOMEM;
	}

	wr_info->bus_wr_ctx[ctx_id]->cre_acquire = data;
	in_acquire = data;
	bus_wr_ctx = wr_info->bus_wr_ctx[ctx_id];
	bus_wr_ctx->num_out_ports = in_acquire->num_out_res;
	bus_wr_ctx->security_flag = in_acquire->secure_mode;

	for (i = 0; i < in_acquire->num_out_res; i++) {
		if (!in_acquire->out_res[i].width)
			continue;

		CAM_DBG(CAM_CRE, "i = %d format = %u width = %x height = %x",
			i, in_acquire->out_res[i].format,
			in_acquire->out_res[i].width,
			in_acquire->out_res[i].height);

		out_port_idx =
		cam_cre_bus_wr_out_port_idx(in_acquire->out_res[i].res_id);
		if (out_port_idx < 0) {
			CAM_DBG(CAM_CRE, "Invalid out_port_idx: %d",
				in_acquire->out_res[i].res_id);
			rc = -EINVAL;
			goto end;
		}
		out_port_to_wr = &wr_info->out_port_to_wm[out_port_idx];
		if (!out_port_to_wr->num_wm) {
			CAM_DBG(CAM_CRE, "Invalid format for Input port");
			rc = -EINVAL;
			goto end;
		}

		bus_wr_ctx->io_port_info.output_port_id[i] =
			in_acquire->out_res[i].res_id;
		bus_wr_ctx->io_port_info.output_format_type[i] =
			in_acquire->out_res[i].format;

		CAM_DBG(CAM_CRE, "i:%d port_id = %u",
			i, bus_wr_ctx->io_port_info.output_port_id[i]);
	}

end:
	return rc;
}

static int cam_cre_bus_wr_init(struct cam_cre_hw *cam_cre_hw_info,
	int32_t ctx_id, void *data)
{
	struct cam_cre_bus_wr_reg_val *bus_wr_reg_val;
	struct cam_cre_bus_wr_reg *bus_wr_reg;
	struct cam_cre_dev_init *dev_init = data;

	if (!cam_cre_hw_info) {
		CAM_ERR(CAM_CRE, "Invalid cam_cre_hw_info");
		return -EINVAL;
	}

	wr_info->cre_hw_info = cam_cre_hw_info;
	bus_wr_reg_val = cam_cre_hw_info->bus_wr_reg_val;
	bus_wr_reg = cam_cre_hw_info->bus_wr_reg_offset;
	bus_wr_reg->base = dev_init->core_info->cre_hw_info->cre_bus_wr_base;

	cam_io_w_mb(bus_wr_reg_val->irq_mask_0,
		cam_cre_hw_info->bus_wr_reg_offset->base +
		bus_wr_reg->irq_mask_0);
	cam_io_w_mb(bus_wr_reg_val->irq_mask_1,
		cam_cre_hw_info->bus_wr_reg_offset->base +
		bus_wr_reg->irq_mask_1);

	return 0;
}

static int cam_cre_bus_wr_probe(struct cam_cre_hw *cam_cre_hw_info,
	int32_t ctx_id, void *data)
{
	int i, k;
	struct cam_cre_bus_wr_reg_val *bus_wr_reg_val;
	struct cre_bus_out_port_to_wm *out_port_to_wm;
	uint32_t output_port_idx;
	uint32_t wm_idx;

	if (!cam_cre_hw_info) {
		CAM_ERR(CAM_CRE, "Invalid cam_cre_hw_info");
		return -EINVAL;
	}
	wr_info = kzalloc(sizeof(struct cre_bus_wr), GFP_KERNEL);
	if (!wr_info) {
		CAM_ERR(CAM_CRE, "Out of memory");
		return -ENOMEM;
	}

	wr_info->cre_hw_info = cam_cre_hw_info;
	bus_wr_reg_val = cam_cre_hw_info->bus_wr_reg_val;

	for (i = 0; i < bus_wr_reg_val->num_clients; i++) {
		output_port_idx =
			bus_wr_reg_val->wr_clients[i].output_port_id - 1;
		out_port_to_wm = &wr_info->out_port_to_wm[output_port_idx];
		wm_idx = out_port_to_wm->num_wm;
		out_port_to_wm->output_port_id =
			bus_wr_reg_val->wr_clients[i].output_port_id;
		out_port_to_wm->wm_port_id[wm_idx] =
			bus_wr_reg_val->wr_clients[i].wm_port_id;
		out_port_to_wm->num_wm++;
	}

	for (i = 0; i < CRE_MAX_OUT_RES; i++) {
		out_port_to_wm = &wr_info->out_port_to_wm[i];
		CAM_DBG(CAM_CRE, "output port id = %d",
			out_port_to_wm->output_port_id);
			CAM_DBG(CAM_CRE, "num_wms = %d",
				out_port_to_wm->num_wm);
			for (k = 0; k < out_port_to_wm->num_wm; k++) {
				CAM_DBG(CAM_CRE, "wm port id = %d",
					out_port_to_wm->wm_port_id[k]);
			}
	}

	return 0;
}

static int cam_cre_bus_wr_isr(struct cam_cre_hw *cam_cre_hw_info,
	int32_t ctx_id, void *data)
{
	uint32_t irq_status_0, irq_status_1;
	struct cam_cre_bus_wr_reg *bus_wr_reg;
	struct cam_cre_bus_wr_reg_val *bus_wr_reg_val;
	struct cam_cre_irq_data *irq_data = data;
	uint32_t debug_status_0;
	uint32_t debug_status_1;
	uint32_t img_violation_status;
	uint32_t violation_status;

	if (!cam_cre_hw_info || !irq_data) {
		CAM_ERR(CAM_CRE, "Invalid cam_cre_hw_info");
		return -EINVAL;
	}

	bus_wr_reg = cam_cre_hw_info->bus_wr_reg_offset;
	bus_wr_reg_val = cam_cre_hw_info->bus_wr_reg_val;

	/* Read and Clear Top Interrupt status */
	irq_status_0 = cam_io_r_mb(bus_wr_reg->base + bus_wr_reg->irq_status_0);
	irq_status_1 = cam_io_r_mb(bus_wr_reg->base + bus_wr_reg->irq_status_1);
	cam_io_w_mb(irq_status_0,
		bus_wr_reg->base + bus_wr_reg->irq_clear_0);
	cam_io_w_mb(irq_status_1,
		bus_wr_reg->base + bus_wr_reg->irq_clear_1);

	cam_io_w_mb(bus_wr_reg_val->irq_cmd_clear,
		bus_wr_reg->base + bus_wr_reg->irq_cmd);

	if (irq_status_0 & bus_wr_reg_val->cons_violation) {
		irq_data->error = 1;
		CAM_ERR(CAM_CRE, "cre bus wr cons_violation");
	}

	if ((irq_status_0 & bus_wr_reg_val->violation) ||
		(irq_status_0 & bus_wr_reg_val->img_size_violation)) {
		irq_data->error = 1;
		img_violation_status = cam_io_r_mb(bus_wr_reg->base +
			bus_wr_reg->image_size_violation_status);
		violation_status = cam_io_r_mb(bus_wr_reg->base +
			bus_wr_reg->violation_status);

		debug_status_0 = cam_io_r_mb(bus_wr_reg->base +
			bus_wr_reg->wr_clients[0].debug_status_0);
		debug_status_1 = cam_io_r_mb(bus_wr_reg->base +
			bus_wr_reg->wr_clients[0].debug_status_1);
		CAM_ERR(CAM_CRE,
			"violation status 0x%x 0x%x debug status 0/1 0x%x/0x%x",
			violation_status, img_violation_status,
			debug_status_0, debug_status_1);
	}

	if (irq_status_1 & bus_wr_reg_val->client_buf_done)
		CAM_INFO(CAM_CRE, "Cleint 0 Buff done");

	return 0;
}

int cam_cre_bus_wr_process(struct cam_cre_hw *cam_cre_hw_info,
	int32_t ctx_id, uint32_t cmd_id, void *data)
{
	int rc = 0;

	switch (cmd_id) {
	case CRE_HW_PROBE:
		CAM_DBG(CAM_CRE, "CRE_HW_PROBE: E");
		rc = cam_cre_bus_wr_probe(cam_cre_hw_info, ctx_id, data);
		CAM_DBG(CAM_CRE, "CRE_HW_PROBE: X");
		break;
	case CRE_HW_INIT:
		CAM_DBG(CAM_CRE, "CRE_HW_INIT: E");
		rc = cam_cre_bus_wr_init(cam_cre_hw_info, ctx_id, data);
		CAM_DBG(CAM_CRE, "CRE_HW_INIT: X");
		break;
	case CRE_HW_ACQUIRE:
		CAM_DBG(CAM_CRE, "CRE_HW_ACQUIRE: E");
		rc = cam_cre_bus_wr_acquire(cam_cre_hw_info, ctx_id, data);
		CAM_DBG(CAM_CRE, "CRE_HW_ACQUIRE: X");
		break;
	case CRE_HW_RELEASE:
		CAM_DBG(CAM_CRE, "CRE_HW_RELEASE: E");
		rc = cam_cre_bus_wr_release(cam_cre_hw_info, ctx_id, data);
		CAM_DBG(CAM_CRE, "CRE_HW_RELEASE: X");
		break;
	case CRE_HW_PREPARE:
		CAM_DBG(CAM_CRE, "CRE_HW_PREPARE: E");
		rc = cam_cre_bus_wr_prepare(cam_cre_hw_info, ctx_id, data);
		CAM_DBG(CAM_CRE, "CRE_HW_PREPARE: X");
		break;
	case CRE_HW_REG_SET_UPDATE:
		rc = cam_cre_bus_wr_reg_set_update(cam_cre_hw_info, 0, data);
		break;
	case CRE_HW_DEINIT:
	case CRE_HW_START:
	case CRE_HW_STOP:
	case CRE_HW_FLUSH:
	case CRE_HW_CLK_UPDATE:
	case CRE_HW_BW_UPDATE:
	case CRE_HW_RESET:
	case CRE_HW_SET_IRQ_CB:
		rc = 0;
		CAM_DBG(CAM_CRE, "Unhandled cmds: %d", cmd_id);
		break;
	case CRE_HW_ISR:
		rc = cam_cre_bus_wr_isr(cam_cre_hw_info, 0, data);
		break;
	default:
		CAM_ERR(CAM_CRE, "Unsupported cmd: %d", cmd_id);
		break;
	}

	return rc;
}
