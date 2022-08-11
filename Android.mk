LOCAL_PATH := $(call my-dir)

all_src_files := \
  $(call all-java-files-under,src/main/java)

# Platform apksig JNI library
include $(CLEAR_VARS)
$(info *my flag* apksig 1)
LOCAL_MODULE := apksig
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := $(all_src_files)
LOCAL_NO_STANDARD_LIBRARIES := true
LOCAL_JAVA_LANGUAGE_VERSION := 1.8

java9_or_greater := $(shell test $(javac_major_version) -ge 9 && echo true)
ifeq ($(java9_or_greater),true)
  # --add-exports flag is only allowed on java9 or greater.
  # TODO(b/162131149) This is just a workaround. We should remove usage of
  # this internal package and use bouncycastle instead.
  LOCAL_JAVACFLAGS := --add-exports java.base/sun.security.pkcs=ALL-UNNAMED \
    --add-exports java.base/sun.security.x509=ALL-UNNAMED
endif
include $(BUILD_HOST_JAVA_LIBRARY)

all_src_files :=
