#!/bin/bash

cd ./server-user/app/bin

qemu-system-aarch64 \
    -nographic \
    -smp 2 -cpu max,sme=on,pauth-impdef=on -d unimp \
    -semihosting-config enable=on,target=native -m 1057 \
    -bios bl1.bin \
    -kernel Image \
    -append 'console=ttyAMA0,38400 keep_bootcon root=/dev/ram0' \
    -netdev user,id=vmnic -device virtio-net-device,netdev=vmnic \
    -machine virt,acpi=off,secure=on,mte=off,gic-version=3,virtualization=false \
    -serial stdio -serial tcp:127.0.0.1:31337 \
    -monitor null \
    -gdb tcp::31338
