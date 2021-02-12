/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017-2021, The Linux Foundation. All rights reserved.
 */

#ifndef _CAM_COMMON_UTIL_H_
#define _CAM_COMMON_UTIL_H_

#include <linux/types.h>
#include <linux/kernel.h>

#define CAM_BITS_MASK_SHIFT(x, mask, shift) (((x) & (mask)) >> shift)

#define PTR_TO_U64(ptr) ((uint64_t)(uintptr_t)ptr)
#define U64_TO_PTR(ptr) ((void *)(uintptr_t)ptr)

#define CAM_GET_TIMESTAMP(timestamp) ktime_get_real_ts64(&(timestamp))
#define CAM_GET_TIMESTAMP_DIFF_IN_MICRO(ts_start, ts_end, diff_microsec)       \
({                                                                             \
	diff_microsec = 0;                                                     \
	if (ts_end.tv_nsec >= ts_start.tv_nsec) {                              \
		diff_microsec =                                                \
			(ts_end.tv_nsec - ts_start.tv_nsec) / 1000;            \
		diff_microsec +=                                               \
			(ts_end.tv_sec - ts_start.tv_sec) * 1000 * 1000;       \
	} else {                                                               \
		diff_microsec =                                                \
			(ts_end.tv_nsec +                                      \
			(1000*1000*1000 - ts_start.tv_nsec)) / 1000;           \
		diff_microsec +=                                               \
			(ts_end.tv_sec - ts_start.tv_sec - 1) * 1000 * 1000;   \
	}                                                                      \
})


/**
 * cam_common_util_get_string_index()
 *
 * @brief                  Match the string from list of strings to return
 *                         matching index
 *
 * @strings:               Pointer to list of strings
 * @num_strings:           Number of strings in 'strings'
 * @matching_string:       String to match
 * @index:                 Pointer to index to return matching index
 *
 * @return:                0 for success
 *                         -EINVAL for Fail
 */
int cam_common_util_get_string_index(const char **strings,
	uint32_t num_strings, const char *matching_string, uint32_t *index);

/**
 * cam_common_util_remove_duplicate_arr()
 *
 * @brief                  Move all the unique integers to the start of
 *                         the array and return the number of unique integers
 *
 * @array:                 Pointer to the first integer of array
 * @num:                   Number of elements in array
 *
 * @return:                Number of unique integers in array
 */
uint32_t cam_common_util_remove_duplicate_arr(int32_t *array,
	uint32_t num);

/**
 * cam_common_wait_for_completion_timeout()
 *
 * @brief                  common interface to implement wait for completion
 *                         for slow environment like presil, single debug
 *                         timeout variable can take care
 *
 * @complete:              Pointer to the first integer of array
 * @timeout_jiffies:       Timeout value in jiffie
 *
 * @return:                Remaining jiffies, non-zero for success, zero
 *                         in case of failure
 */
unsigned long cam_common_wait_for_completion_timeout(
	struct completion   *complete,
	unsigned long        timeout_jiffies);
/**
 * cam_common_read_poll_timeout()
 *
 * @brief                  common interface to read poll timeout
 *
 * @addr:                  Address of IO register
 * @delay:                 Delay interval of poll
 * @timeout:               Timeout for poll
 * @mask:                  Mask to be checked
 * @check_val:             Value to be compared to break poll
 * @status:                Status of register of IO
 *
 * @return:                0 if success and negative if fail
 * */
int cam_common_read_poll_timeout(
	void __iomem        *addr,
	unsigned long        delay,
	unsigned long        timeout,
	uint32_t             mask,
	uint32_t             check_val,
	uint32_t            *status);
#endif /* _CAM_COMMON_UTIL_H_ */
