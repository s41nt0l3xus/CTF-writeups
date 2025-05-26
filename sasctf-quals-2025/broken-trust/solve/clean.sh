#!/bin/bash

./docker.sh make -C /work/xploit/ \
  TEEC_EXPORT=/work/optee/out-br/per-package/optee_client_ext/target/usr \
  TA_DEV_KIT_DIR=/work/optee/optee_os/out/arm/export-ta_arm64 \
  CROSS_COMPILE=aarch64-none-linux-gnu- \
  clean
