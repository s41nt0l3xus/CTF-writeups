#!/bin/bash

cd /chall
adb start server
./helper init &
./helper emu
