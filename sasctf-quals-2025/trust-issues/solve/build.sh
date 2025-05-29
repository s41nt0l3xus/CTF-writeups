#!/bin/bash

set -e

if [[ ! -d ./optee ]]; then
  mkdir ./optee
  cd ./optee
  repo init -u https://github.com/OP-TEE/manifest.git -b 4.5.0 
  repo sync
  cd ../
  ./docker.sh make -C /work/optee/build toolchains
  # We call it "Magiya drevnih rusov"
  ./docker.sh make -C /work/optee/build -j$((`nproc`+1)) || ./docker.sh make -C /work/optee/build -j$((`nproc`+1))
fi

./docker.sh make -C /work/xploit/host -j$((`nproc`+1)) \
  TEEC_EXPORT=/work/optee/out-br/per-package/optee_client_ext/target/usr \
  CROSS_COMPILE=arm-none-linux-gnueabihf- \
  $@
