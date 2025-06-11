#!/bin/bash

docker run \
  -d \
  --rm \
  --name cratecrack \
  --net=host \
  --privileged \
  -v /dev/kvm:/dev/kvm \
  -v .:/work \
  cratecrack
