#!/bin/bash
export PATCHED_KERNEL=$(mktemp /tmp/patched-kernel.XXXXXXXXXX)
export LOG_DIR=$(mktemp /tmp/skp-log-file.XXXXXXXXXX)
echo $1
just patch-kernel $1 $2 $PATCHED_KERNEL 1>/dev/null 2>/dev/null

if ! ./src/scripts/test.sh 30 bios $LOG_DIR 2>/dev/null; then
    echo "$1 - BIOS FAILED"
fi

if ! ./src/scripts/test.sh 30 uefi $LOG_DIR 2>/dev/null; then
    echo "$1 - UEFI FAILED"
fi

rm $PATCHED_KERNEL $LOG_DIR
