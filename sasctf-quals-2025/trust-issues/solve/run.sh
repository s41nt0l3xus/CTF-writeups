#!/bin/bash

cd ./task/bin

qemu-system-arm \
  -nographic \
  -smp 2 -d unimp \
  -semihosting-config enable=on,target=native \
  -m 1057 -bios bl1.bin -machine virt,secure=on \
  -cpu cortex-a15 -object rng-random,filename=/dev/urandom,id=rng0 \
  -device virtio-rng-pci,rng=rng0,max-bytes=1024,period=1000 \
  -netdev user,id=vmnic \
  -device virtio-net-device,netdev=vmnic \
  -monitor null \
  -serial stdio -serial tcp:127.0.0.1:31337 -s
