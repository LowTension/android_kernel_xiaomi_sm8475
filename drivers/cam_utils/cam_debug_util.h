/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017-2021, The Linux Foundation. All rights reserved.
 */

#ifndef _CAM_DEBUG_UTIL_H_
#define _CAM_DEBUG_UTIL_H_

#include <linux/platform_device.h>

/* Module IDs used for debug logging */
#define CAM_CDM           BIT_ULL(0)
#define CAM_CORE          BIT_ULL(1)
#define CAM_CPAS          BIT_ULL(2)
#define CAM_ISP           BIT_ULL(3)
#define CAM_CRM           BIT_ULL(4)
#define CAM_SENSOR        BIT_ULL(5)
#define CAM_SMMU          BIT_ULL(6)
#define CAM_SYNC          BIT_ULL(7)
#define CAM_ICP           BIT_ULL(8)
#define CAM_JPEG          BIT_ULL(9)
#define CAM_FD            BIT_ULL(10)
#define CAM_LRME          BIT_ULL(11)
#define CAM_FLASH         BIT_ULL(12)
#define CAM_ACTUATOR      BIT_ULL(13)
#define CAM_CCI           BIT_ULL(14)
#define CAM_CSIPHY        BIT_ULL(15)
#define CAM_EEPROM        BIT_ULL(16)
#define CAM_UTIL          BIT_ULL(17)
#define CAM_HFI           BIT_ULL(18)
#define CAM_CTXT          BIT_ULL(19)
#define CAM_OIS           BIT_ULL(20)
#define CAM_RES           BIT_ULL(21)
#define CAM_MEM           BIT_ULL(22)
#define CAM_IRQ_CTRL      BIT_ULL(23)
#define CAM_REQ           BIT_ULL(24)
#define CAM_PERF          BIT_ULL(25)
#define CAM_CUSTOM        BIT_ULL(26)
#define CAM_PRESIL        BIT_ULL(27)
#define CAM_OPE           BIT_ULL(28)
#define CAM_IO_ACCESS     BIT_ULL(29)
#define CAM_SFE           BIT_ULL(30)
#define CAM_CRE           BIT_ULL(31)
#define CAM_PRESIL_CORE   BIT_ULL(32)

/* Log level types */
#define CAM_TYPE_TRACE      (1 << 0)
#define CAM_TYPE_ERR        (1 << 1)
#define CAM_TYPE_WARN       (1 << 2)
#define CAM_TYPE_INFO       (1 << 3)
#define CAM_TYPE_DBG        (1 << 4)

#define STR_BUFFER_MAX_LENGTH  512

/*
 * enum cam_debug_priority - Priority of debug log (0 = Lowest)
 */
enum cam_debug_priority {
	CAM_DBG_PRIORITY_0,
	CAM_DBG_PRIORITY_1,
	CAM_DBG_PRIORITY_2,
};

/**
 * struct cam_cpas_debug_settings - Sysfs debug settings for cpas driver
 */
struct cam_cpas_debug_settings {
	uint64_t mnoc_hf_0_ab_bw;
	uint64_t mnoc_hf_0_ib_bw;
	uint64_t mnoc_hf_1_ab_bw;
	uint64_t mnoc_hf_1_ib_bw;
	uint64_t mnoc_sf_0_ab_bw;
	uint64_t mnoc_sf_0_ib_bw;
	uint64_t mnoc_sf_1_ab_bw;
	uint64_t mnoc_sf_1_ib_bw;
	uint64_t mnoc_sf_icp_ab_bw;
	uint64_t mnoc_sf_icp_ib_bw;
	uint64_t camnoc_bw;
};

/**
 * struct camera_debug_settings - Sysfs debug settings for camera
 *
 * @cpas_settings: Debug settings for cpas driver.
 */
struct camera_debug_settings {
	struct cam_cpas_debug_settings cpas_settings;
};

/*
 *  cam_debug_log()
 *
 * @brief     :  Get the Module name from module ID and print
 *               respective debug logs
 *
 * @module_id :  Respective Module ID which is calling this function
 * @priority  :  Priority of the debug log
 * @func      :  Function which is calling to print logs
 * @line      :  Line number associated with the function which is calling
 *               to print log
 * @fmt       :  Formatted string which needs to be print in the log
 *
 */
void cam_debug_log(unsigned long long module_id, unsigned int priority,
	const char *func, const int line, const char *fmt, ...);

/*
 *  cam_debug_trace()
 *
 * @brief     :  Get the Module name from module ID and print
 *               respective debug logs in ftrace
 *
 * @tag       :  Tag indicating whether TRACE, ERR, WARN, INFO, DBG
 * @module_id :  Respective Module ID which is calling this function
 * @func      :  Function which is calling to print logs
 * @line      :  Line number associated with the function which is calling
 *               to print log
 * @fmt       :  Formatted string which needs to be print in the log
 *
 */
void cam_debug_trace(unsigned int tag, unsigned long long module_id,
	const char *func, const int line, const char *fmt, ...);

/*
 * cam_get_module_name()
 *
 * @brief     :  Get the module name from module ID
 *
 * @module_id :  Module ID which is using this function
 */
const char *cam_get_module_name(unsigned long long module_id);

/*
 * CAM_TRACE
 * @brief    :  This Macro will print logs in ftrace
 *
 * @__module :  Respective module id which is been calling this Macro
 * @fmt      :  Formatted string which needs to be print in log
 * @args     :  Arguments which needs to be print in log
 */
#define CAM_TRACE(__module, fmt, args...)                                      \
	({                                                                     \
		cam_debug_trace(CAM_TYPE_TRACE, __module, __func__, __LINE__,  \
			fmt, ##args);                                          \
	})

/*
 * CAM_ERR
 * @brief    :  This Macro will print error logs
 *
 * @__module :  Respective module id which is been calling this Macro
 * @fmt      :  Formatted string which needs to be print in log
 * @args     :  Arguments which needs to be print in log
 */
#define CAM_ERR(__module, fmt, args...)                                        \
	({                                                                     \
		pr_info("CAM_ERR: %s: %s: %d " fmt "\n",                       \
			cam_get_module_name(__module), __func__,               \
			__LINE__, ##args);                                     \
		cam_debug_trace(CAM_TYPE_ERR, __module, __func__, __LINE__,    \
			fmt, ##args);                                          \
	})

/*
 * CAM_WARN
 * @brief    :  This Macro will print warning logs
 *
 * @__module :  Respective module id which is been calling this Macro
 * @fmt      :  Formatted string which needs to be print in log
 * @args     :  Arguments which needs to be print in log
 */
#define CAM_WARN(__module, fmt, args...)                                       \
	({                                                                     \
		pr_info("CAM_WARN: %s: %s: %d " fmt "\n",                      \
			cam_get_module_name(__module), __func__,               \
			__LINE__, ##args);                                     \
		cam_debug_trace(CAM_TYPE_ERR, __module, __func__, __LINE__,    \
			fmt, ##args);                                          \
	})

/*
 * CAM_INFO
 * @brief    :  This Macro will print Information logs
 *
 * @__module :  Respective module id which is been calling this Macro
 * @fmt      :  Formatted string which needs to be print in log
 * @args     :  Arguments which needs to be print in log
 */
#define CAM_INFO(__module, fmt, args...)                                       \
	({                                                                     \
		pr_info("CAM_INFO: %s: %s: %d " fmt "\n",                      \
			cam_get_module_name(__module), __func__,               \
			__LINE__, ##args);                                     \
		cam_debug_trace(CAM_TYPE_INFO, __module, __func__, __LINE__,   \
			fmt, ##args);                                          \
	})

/*
 * CAM_INFO_RATE_LIMIT
 * @brief    :  This Macro will print info logs with ratelimit
 *
 * @__module :  Respective module id which is been calling this Macro
 * @fmt      :  Formatted string which needs to be print in log
 * @args     :  Arguments which needs to be print in log
 */
#define CAM_INFO_RATE_LIMIT(__module, fmt, args...)                            \
	({                                                                     \
		pr_info_ratelimited("CAM_INFO: %s: %s: %d " fmt "\n",          \
			cam_get_module_name(__module), __func__,               \
			__LINE__, ##args);                                     \
		cam_debug_trace(CAM_TYPE_INFO, __module, __func__, __LINE__,   \
			fmt, ##args);                                          \
	})

/*
 * CAM_DBG
 * @brief    :  This Macro will print debug logs when enabled using GROUP and
 *              if its priority is greater than the priority parameter
 *
 * @__module :  Respective module id which is been calling this Macro
 * @fmt      :  Formatted string which needs to be print in log
 * @args     :  Arguments which needs to be print in log
 */
#define CAM_DBG(__module, fmt, args...)                                        \
	cam_debug_log(__module, CAM_DBG_PRIORITY_0, __func__, __LINE__,        \
			fmt, ##args)
#define CAM_DBG_PR1(__module, fmt, args...)                                    \
	cam_debug_log(__module, CAM_DBG_PRIORITY_1, __func__, __LINE__,        \
			fmt, ##args)
#define CAM_DBG_PR2(__module, fmt, args...)                                    \
	cam_debug_log(__module, CAM_DBG_PRIORITY_2, __func__, __LINE__,        \
			fmt, ##args)

/*
 * CAM_ERR_RATE_LIMIT
 * @brief    :  This Macro will print error print logs with ratelimit
 */
#define CAM_ERR_RATE_LIMIT(__module, fmt, args...)                             \
	({                                                                     \
		pr_info_ratelimited("CAM_ERR: %s: %s: %d " fmt "\n",           \
			cam_get_module_name(__module), __func__,               \
			__LINE__, ##args);                                     \
		cam_debug_trace(CAM_TYPE_INFO, __module, __func__, __LINE__,   \
			fmt, ##args);                                          \
	})
/*
 * CAM_WARN_RATE_LIMIT
 * @brief    :  This Macro will print warning logs with ratelimit
 *
 * @__module :  Respective module id which is been calling this Macro
 * @fmt      :  Formatted string which needs to be print in log
 * @args     :  Arguments which needs to be print in log
 */
#define CAM_WARN_RATE_LIMIT(__module, fmt, args...)                            \
	({                                                                     \
		pr_info_ratelimited("CAM_WARN: %s: %s: %d " fmt "\n",          \
			cam_get_module_name(__module), __func__,               \
			__LINE__, ##args);                                     \
		cam_debug_trace(CAM_TYPE_WARN, __module, __func__, __LINE__,   \
			fmt, ##args);                                          \
	})

/*
 * CAM_WARN_RATE_LIMIT_CUSTOM
 * @brief    :  This Macro will print warn logs with custom ratelimit
 *
 * @__module :  Respective module id which is been calling this Macro
 * @interval :  Time interval in seconds
 * @burst    :  No of logs to print in interval time
 * @fmt      :  Formatted string which needs to be print in log
 * @args     :  Arguments which needs to be print in log
 */
#define CAM_WARN_RATE_LIMIT_CUSTOM(__module, interval, burst, fmt, args...)    \
	({                                                                     \
		static DEFINE_RATELIMIT_STATE(_rs,                             \
			(interval * HZ),                                       \
			burst);                                                \
		if (__ratelimit(&_rs))                                         \
			pr_info(                                               \
				"CAM_WARN: %s: %s: %d " fmt "\n",              \
				cam_get_module_name(__module), __func__,       \
				__LINE__, ##args);                             \
		cam_debug_trace(CAM_TYPE_WARN, __module, __func__, __LINE__,   \
			fmt, ##args);                                          \
	})

/*
 * CAM_INFO_RATE_LIMIT_CUSTOM
 * @brief    :  This Macro will print info logs with custom ratelimit
 *
 * @__module :  Respective module id which is been calling this Macro
 * @interval :  Time interval in seconds
 * @burst    :  No of logs to print in interval time
 * @fmt      :  Formatted string which needs to be print in log
 * @args     :  Arguments which needs to be print in log
 */
#define CAM_INFO_RATE_LIMIT_CUSTOM(__module, interval, burst, fmt, args...)    \
	({                                                                     \
		static DEFINE_RATELIMIT_STATE(_rs,                             \
			(interval * HZ),                                       \
			burst);                                                \
		if (__ratelimit(&_rs))                                         \
			pr_info(                                               \
				"CAM_INFO: %s: %s: %d " fmt "\n",              \
				cam_get_module_name(__module), __func__,       \
				__LINE__, ##args);                             \
		cam_debug_trace(CAM_TYPE_INFO, __module, __func__, __LINE__,   \
			fmt, ##args);                                          \
	})

/*
 * CAM_ERR_RATE_LIMIT_CUSTOM
 * @brief    :  This Macro will print error logs with custom ratelimit
 *
 * @__module :  Respective module id which is been calling this Macro
 * @interval :  Time interval in seconds
 * @burst    :  No of logs to print in interval time
 * @fmt      :  Formatted string which needs to be print in log
 * @args     :  Arguments which needs to be print in log
 */
#define CAM_ERR_RATE_LIMIT_CUSTOM(__module, interval, burst, fmt, args...)    \
	({                                                                    \
		static DEFINE_RATELIMIT_STATE(_rs,                            \
			(interval * HZ),                                      \
			burst);                                               \
		if (__ratelimit(&_rs))                                        \
			pr_info(                                              \
				"CAM_ERR: %s: %s: %d " fmt "\n",              \
				cam_get_module_name(__module), __func__,      \
				__LINE__, ##args);                            \
		cam_debug_trace(CAM_TYPE_ERR, __module, __func__, __LINE__,   \
			fmt, ##args);                                         \
	})

/**
 * cam_print_to_buffer
 * @brief:         Function to print to camera logs to a buffer. Don't use directly. Use macros
 *                 provided below.
 *
 * @buf:           Buffer to print into
 * @buf_size:      Total size of the buffer
 * @len:           Pointer to variable used to keep track of the length
 * @tag:           Log level tag to be prefixed
 * @module_id:     Module id tag to be prefixed
 * @fmt:           Formatted string which needs to be print in log
 * @args:          Arguments which needs to be print in log
 */
void cam_print_to_buffer(char *buf, const size_t buf_size, size_t *len, unsigned int tag,
	unsigned long long module_id, const char *fmt, ...);

/**
 * CAM_[ERR/WARN/INFO]_BUF
 * @brief:         Macro to print a new line into log buffer.
 *
 * @module_id:     Module id tag to be prefixed
 * @buf:           Buffer to print into
 * @buf_size:      Total size of the buffer
 * @len:           Pointer to the variable used to keep track of the length
 * @fmt:           Formatted string which needs to be print in log
 * @args:          Arguments which needs to be print in log
 */
#define CAM_ERR_BUF(module_id, buf, buf_size, len, fmt, args...)                                   \
	cam_print_to_buffer(buf, buf_size, len, CAM_TYPE_ERR, module_id, fmt, ##args)
#define CAM_WARN_BUF(module_id, buf, buf_size, len, fmt, args...)                                  \
	cam_print_to_buffer(buf, buf_size, len, CAM_TYPE_WARN, module_id, fmt, ##args)
#define CAM_INFO_BUF(module_id, buf, buf_size, len, fmt, args...)                                  \
	cam_print_to_buffer(buf, buf_size, len, CAM_TYPE_INFO, module_id, fmt, ##args)

/**
 * @brief : API to get camera debug settings
 * @return const struct camera_debug_settings pointer.
 */
const struct camera_debug_settings *cam_debug_get_settings(void);

/**
 * @brief : API to parse and store input from sysfs debug node
 * @return Number of bytes read from buffer on success, or -EPERM on error.
 */
ssize_t cam_debug_sysfs_node_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

#endif /* _CAM_DEBUG_UTIL_H_ */
