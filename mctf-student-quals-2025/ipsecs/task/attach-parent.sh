#!/bin/bash

docker exec -i ipsecs bash -c 'kill -9 `pidof gdbserver`'
docker exec -i ipsecs bash -c 'gdbserver --attach :11112 `pidof ipsecs`' &
sleep 2
gdb \
  -ex 'target remote :11112' \
  -ex 'set follow-fork-mode parent' \
  -ex 'set detach-on-fork on' \
  -ex 'brva 0x1AD1' \
  -ex 'c'
