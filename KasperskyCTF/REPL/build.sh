#!/usr/bin/bash

gcc -o chall -fstack-protector -fPIE -Wall -Wextra chall.c -Wl,-z,relro,-z,now
