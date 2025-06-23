#!/bin/sh

socat -v TCP-LISTEN:14140,reuseaddr,fork EXEC:"./run.sh",stderr
