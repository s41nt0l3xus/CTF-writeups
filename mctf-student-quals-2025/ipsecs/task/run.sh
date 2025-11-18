#!/bin/bash
socat tcp-listen:11111,reuseaddr,fork exec:"./ipsecs"

