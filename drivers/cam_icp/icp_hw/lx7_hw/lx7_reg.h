/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#ifndef _CAM_LX7_REG_H_
#define _CAM_LX7_REG_H_

#define ICP_LX7_CIRQ_OB_MASK   0x0
#define ICP_LX7_CIRQ_OB_CLEAR  0x4
#define ICP_LX7_CIRQ_OB_STATUS 0xc

/* These bitfields are shared by OB_MASK, OB_CLEAR, OB_STATUS */
#define LX7_WDT_BITE_WS1       (1 << 6)
#define LX7_WDT_BARK_WS1       (1 << 5)
#define LX7_WDT_BITE_WS0       (1 << 4)
#define LX7_WDT_BARK_WS0       (1 << 3)
#define LX7_ICP2HOSTINT        (1 << 2)

#define ICP_LX7_CIRQ_OB_IRQ_CMD 0x10
#define LX7_IRQ_CLEAR_CMD       (1 << 1)

#define ICP_LX7_CIRQ_HOST2ICPINT 0x124
#define LX7_HOST2ICPINT          (1 << 0)

#endif /* _CAM_LX7_REG_H_ */
