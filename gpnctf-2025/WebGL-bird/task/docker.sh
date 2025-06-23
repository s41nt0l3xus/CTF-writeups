#!/bin/bash

docker run \
  -d \
  --rm \
  --name ladybird \
  -v .:/shared \
  -p 14140:14140 \
  -p 31337:31337 \
  --privileged \
  --cap-add SYS_PTRACE \
  ladybird
