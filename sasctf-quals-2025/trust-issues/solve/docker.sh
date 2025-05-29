#!/bin/bash

docker run \
  -it \
  --rm \
  --name xploit \
  -v .:/work \
  xploit \
  $@ 
