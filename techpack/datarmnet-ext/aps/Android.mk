ifneq ($(TARGET_BOARD_AUTO),true)
ifneq ($(TARGET_BOARD_PLATFORM),qssi)

RMNET_APS_DLKM_PLATFORMS_LIST := taro
RMNET_APS_DLKM_PLATFORMS_LIST += parrot

ifeq ($(call is-board-platform-in-list, $(RMNET_APS_DLKM_PLATFORMS_LIST)),true)
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := rmnet_aps.ko
LOCAL_MODULE_PATH := $(KERNEL_MODULES_OUT)
LOCAL_SRC_FILES := $(wildcard $(LOCAL_PATH)/**/*) $(wildcard $(LOCAL_PATH)/*)

DATARMNET_CORE_PATH := datarmnet/core
RMNET_CORE_PATH := vendor/qcom/opensource/$(DATARMNET_CORE_PATH)
DLKM_DIR := $(TOP)/device/qcom/common/dlkm
RMNET_CORE_INC_DIR := $(abspath $(RMNET_CORE_PATH))

KBUILD_OPTIONS := RMNET_CORE_INC_DIR=$(RMNET_CORE_INC_DIR)
KBUILD_OPTIONS += RMNET_CORE_PATH=$(RMNET_CORE_PATH)
KBUILD_OPTIONS += DATARMNET_CORE_PATH=$(DATARMNET_CORE_PATH)
KBUILD_OPTIONS_GKI := RMNET_CORE_INC_DIR=$(RMNET_CORE_INC_DIR)
KBUILD_OPTIONS_GKI += RMNET_CORE_PATH=$(RMNET_CORE_PATH)/gki

#Must be built after the core rmnet module
LOCAL_ADDITIONAL_DEPENDENCIES := $(TARGET_OUT_INTERMEDIATES)/DLKM_OBJ/$(RMNET_CORE_PATH)/rmnet_core.ko
LOCAL_ADDITIONAL_DEPENDENCIES_GKI := $(TARGET_OUT_INTERMEDIATES)/DLKM_OBJ/$(RMNET_CORE_PATH)/gki/rmnet_core.ko

include $(DLKM_DIR)/Build_external_kernelmodule.mk

endif #End of check for target
endif #End of Check for qssi target
endif #End of check for AUTO Target
