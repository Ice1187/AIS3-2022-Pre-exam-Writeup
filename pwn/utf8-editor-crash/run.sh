#!/bin/sh
cd /app
./chall
if [ $? -eq 139 ]; then
    cat crash-flag.txt
fi
