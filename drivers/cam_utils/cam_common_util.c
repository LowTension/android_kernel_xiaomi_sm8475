// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2017-2021, The Linux Foundation. All rights reserved.
 */

#include <linux/string.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/timer.h>
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

int cam_common_modify_timer(struct timer_list *timer, int32_t timeout_val)
{
	if (!timer) {
		CAM_ERR(CAM_UTIL, "Invalid reference to system timer");
		return -EINVAL;
	}

	if (timeout_multiplier < 1)
		timeout_multiplier = 1;

	CAM_DBG(CAM_UTIL, "Starting timer to fire in %d ms. (jiffies=%lu)\n",
		(timeout_val * timeout_multiplier), jiffies);
	mod_timer(timer,
		(jiffies + msecs_to_jiffies(timeout_val * timeout_multiplier)));

	return 0;
}

void cam_common_util_thread_switch_delay_detect(
	const char *token, ktime_t scheduled_time, uint32_t threshold)
{
	uint64_t                         diff;
	ktime_t                          cur_time;
	struct timespec64                cur_ts;
	struct timespec64                scheduled_ts;

	cur_time = ktime_get();
	diff = ktime_ms_delta(cur_time, scheduled_time);

	if (diff > threshold) {
		scheduled_ts  = ktime_to_timespec64(scheduled_time);
		cur_ts = ktime_to_timespec64(cur_time);
		CAM_WARN_RATE_LIMIT_CUSTOM(CAM_UTIL, 1, 1,
			"%s delay detected %ld:%06ld cur %ld:%06ld diff %ld: threshold %d",
			token, scheduled_ts.tv_sec,
			scheduled_ts.tv_nsec/NSEC_PER_USEC,
			cur_ts.tv_sec, cur_ts.tv_nsec/NSEC_PER_USEC,
			diff, threshold);
	}
}
