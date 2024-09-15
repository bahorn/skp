#!/bin/bash
just patch-kernel $1 $2 1>/dev/null 2>/dev/null
echo $1
if ! ./src/scripts/test.sh 30 bios 2>/dev/null; then
    echo "BIOS FAILED"
fi
if ! ./src/scripts/test.sh 30 uefi 2>/dev/null; then
    echo "UEFI FAILED"
fi
