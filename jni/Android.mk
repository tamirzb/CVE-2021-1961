LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := QSEEComAPI
LOCAL_SRC_FILES := QSEEComAPI_dummy.c
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := qseecom_exploit
LOCAL_SRC_FILES := main.c widevine.c ion.c exploit.c kallsyms.c
LOCAL_SHARED_LIBRARIES := QSEEComAPI
include $(BUILD_EXECUTABLE)
