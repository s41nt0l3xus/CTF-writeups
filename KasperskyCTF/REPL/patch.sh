#!/usr/bin/bash

cp chall chall.patched
patchelf --set-interpreter ./ld-linux-x86-64.so.2 chall.patched
patchelf --set-rpath . chall.patched
