/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * All rights reserved.
 */

#include <linux/types.h>

#ifndef _QCOM_BUS_PROF_H
#define _QCOM_BUS_PROF_H
#define MAX_CONCURRENT_MASTERS	2

struct llcc_miss_buf {
	u8		master_id;
	u16		miss_info;
	u32		rd_miss;
	u32		wr_miss;
	u32		all_access;
} __packed;


struct llcc_occ_buf {
	u8		master_id;
	u16		occ_info;
	u32		max_cap;
	u32		curr_cap;
} __packed;
#endif /* _QCOM_BUS_PROF_H */
