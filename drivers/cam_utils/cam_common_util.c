// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2017-2021, The Linux Foundation. All rights reserved.
 */

#include <linux/string.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/module.h>
#include <linux/iopoll.h>
#include <linux/moduleparam.h>
#include "cam_common_util.h"
#include "cam_debug_util.h"

static uint timeout_multiplier = 1;
module_param(timeout_multiplier, uint, 0644);

int cam_common_util_get_string_index(const char **strings,
	uint32_t num_strings, const char *matching_string, uint32_t *index)
{
	int i;

	for (i = 0; i < num_strings; i++) {
		if (strnstr(strings[i], matching_string, strlen(strings[i]))) {
			CAM_DBG(CAM_UTIL, "matched %s : %d\n",
				matching_string, i);
			*index = i;
			return 0;
		}
	}

	return -EINVAL;
}

uint32_t cam_common_util_remove_duplicate_arr(int32_t *arr, uint32_t num)
{
	int i, j;
	uint32_t wr_idx = 1;

	if (!arr) {
		CAM_ERR(CAM_UTIL, "Null input array");
		return 0;
	}

	for (i = 1; i < num; i++) {
		for (j = 0; j < wr_idx ; j++) {
			if (arr[i] == arr[j])
				break;
		}
		if (j == wr_idx)
			arr[wr_idx++] = arr[i];
	}

	return wr_idx;
}

unsigned long cam_common_wait_for_completion_timeout(
	struct completion   *complete,
	unsigned long        timeout_jiffies)
{
	unsigned long wait_jiffies;
	unsigned long rem_jiffies;

	if (!complete) {
		CAM_ERR(CAM_UTIL, "Null complete pointer");
		return 0;
	}

	if (timeout_multiplier < 1)
		timeout_multiplier = 1;

	wait_jiffies = timeout_jiffies * timeout_multiplier;
	rem_jiffies = wait_for_completion_timeout(
			complete, wait_jiffies);

	return rem_jiffies;
}

int cam_common_read_poll_timeout(
	void __iomem        *addr,
	unsigned long        delay,
	unsigned long        timeout,
	uint32_t             mask,
	uint32_t             check_val,
	uint32_t            *status)
{
	unsigned long wait_time_us;
	int rc = -EINVAL;

	if (!addr || !status) {
		CAM_ERR(CAM_UTIL, "Invalid param addr: %pK status: %pK",
			addr, status);
		return rc;
	}

	if (timeout_multiplier < 1)
		timeout_multiplier = 1;

	wait_time_us = timeout * timeout_multiplier;
	rc = readl_poll_timeout(addr,
		*status, (*status & mask) == check_val, delay, wait_time_us);

	return rc;
}
