#!/bin/bash

set -e

if [[ ! -d ./optee ]]; then
  mkdir ./optee
  cd ./optee
  repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml -b 4.5.0 
  repo sync
  cd ../
  ./docker.sh make -C /work/optee/build toolchains
  ./docker.sh make -C /work/optee/build -j$((`nproc`+1))
fi

./docker.sh make -C /work/xploit/ -j$((`nproc`+1)) \
  TEEC_EXPORT=/work/optee/out-br/per-package/optee_client_ext/target/usr \
  TA_DEV_KIT_DIR=/work/optee/optee_os/out/arm/export-ta_arm64 \
  CROSS_COMPILE=aarch64-none-linux-gnu-
