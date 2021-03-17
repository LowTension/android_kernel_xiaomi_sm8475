/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#ifndef __UAPI_CAM_CRE_H__
#define __UAPI_CAM_CRE_H__

#include <media/cam_defs.h>
#include <media/cam_cpas.h>

#define CAM_CRE_DEV_NAME_SIZE     128

/* CRE HW TYPE */
#define CAM_CRE_HW_TYPE_CRE       0x1
#define CAM_CRE_HW_TYPE_MAX       0x2

/* packet opcode types */
#define CAM_CRE_OPCODE_CONFIG     0x1

/* input port resource type */
#define CAM_CRE_INPUT_IMAGE       0x1
#define CAM_CRE_INPUT_IMAGES_MAX  (CAM_CRE_INPUT_IMAGE + 1)

/* output port resource type */
#define CAM_CRE_OUTPUT_IMAGE      0x1
#define CAM_CRE_OUTPUT_IMAGES_MAX (CAM_CRE_OUTPUT_IMAGE + 1)

/* definitions needed for cre aquire device */
#define CAM_CRE_DEV_TYPE_NRT      0x1
#define CAM_CRE_DEV_TYPE_RT       0x2
#define CAM_CRE_DEV_TYPE_MAX      0x3

/* Clock blob */
#define CAM_CRE_CMD_GENERIC_BLOB_CLK      0x1

#define CAM_CRE_MAX_PLANES                0x2
#define CRE_MAX_BATCH_SIZE                0x10
#define CAM_CRE_MAX_IO_BUFS               0x3

#define CAM_CRE_ACQUIRE_FLAG_SECURE  0x1

/**
 * struct cam_cre_io_buf_info - CRE IO buffers meta
 *
 * @direction:     Direction of a buffer of a port(Input/Output)
 * @res_id:        Resource ID
 * @num_planes:    Number of planes
 * @width:         Height of a plane buffer
 * @height:        Height of a plane buffer
 * @stride:        Plane stride
 * @packer_format: Format
 * @alignment:     Alignment
 * @reserved:      Reserved field 0
 * @reserved_1:    Reserved field 1
 * @reserved_2:    Reserved field 2
 *
 */
struct cam_cre_io_buf_info {
	__u32 direction;
	__u32 res_id;
	__u32 num_planes;
	__u32 width;
	__u32 height;
	__u32 stride;
	__u32 fence;
	__u32 packer_format;
	__u32 alignment;
	__u32 reserved;
	__u32 reserved_1;
	__u32 reserved_2;
};

/**
 * struct cam_cre_hw_ver - Device information for particular hw type
 *
 * This is used to get device version info of CRE
 * from hardware and use this info in CAM_QUERY_CAP IOCTL
 *
 * @hw_type:   Hardware type
 * @reserved:  Reserved field
 * @hw_ver:    Major, minor and incr values of a device version
 */
struct cam_cre_hw_ver {
	__u32  hw_type;
	__u32  reserved;
	struct cam_hw_version hw_ver;
};

/**
 * struct cam_cre_query_cap_cmd - CRE query device capability payload
 *
 * @dev_iommu_handle: CRE iommu handles for secure/non secure modes
 * @num_dev:          Number of cre
 * @reserved:         Reserved field
 * @dev_ver:          Returned device capability array
 */
struct cam_cre_query_cap_cmd {
	struct cam_iommu_handle dev_iommu_handle;
	__u32                   num_dev;
	__u32                   reserved;
	struct cam_cre_hw_ver   dev_ver[CAM_CRE_HW_TYPE_MAX];
};

/**
 * struct cam_cre_clk_bw_request
 *
 * @budget_ns: Time required to process frame
 * @frame_cycles: Frame cycles needed to process the frame
 * @rt_flag: Flag to indicate real time stream
 * @uncompressed_bw: Bandwidth required to process frame
 * @compressed_bw: Compressed bandwidth to process frame
 * @reserved:      Reserved field 0
 * @reserved_1:    Reserved field 1
 * @reserved_2:    Reserved field 2
 * @num_path:      Number of AXI Paths
 */
struct cam_cre_clk_bw_request {
	__u64  budget_ns;
	__u32  frame_cycles;
	__u32  rt_flag;
	__u64  uncompressed_bw;
	__u64  compressed_bw;
	__u32  num_paths;
	__u32  reserved;
	__u32  reserved_1;
	__u32  reserved_2;
	struct cam_axi_per_path_bw_vote axi_path[1];
};

/**
 * struct cam_cre_acquire_dev_info - An CRE device info
 *
 * @dev_type:      NRT/RT Acquire
 * @dev_name:      Device name (CRE)
 * @acquire_flag:  Tells if CRE will process the secure buff or not.
 * @batch_size:    Batch size
 * @num_in_res:    Number of In resources
 * @num_out_res:   Number of Out resources
 * @reserved:      Reserved field 0
 * @reserved_1:    Reserved field 1
 * @reserved_2:    Reserved field 2
 * @in_res:        In resource info
 * @in_res:        Out resource info
 */
struct cam_cre_acquire_dev_info {
	__u32                      dev_type;
	char                       dev_name[CAM_CRE_DEV_NAME_SIZE];
	__u32                      acquire_flag;
	__u32                      batch_size;
	__u32                      num_in_res;
	__u32                      num_out_res;
	__u32                      reserved;
	__u32                      reserved_1;
	__u32                      reserved_2;
	struct cam_cre_io_buf_info in_res[CAM_CRE_INPUT_IMAGES_MAX];
	struct cam_cre_io_buf_info out_res[CAM_CRE_OUTPUT_IMAGES_MAX];
}__attribute__((__packed__));

#endif /* __UAPI_CAM_CRE_H__ */
