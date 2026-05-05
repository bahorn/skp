#!/bin/bash
export PATCHED_KERNEL=$(mktemp -u /tmp/patched-kernel.XXXXXXXXXX)
export LOG_DIR=$(mktemp -u /tmp/skp-log-file.XXXXXXXXXX)
echo $1
just --set skip_build_runtime true patch-kernel $1 $PATCHED_KERNEL $2 1>/dev/null 2>/dev/null

if ! ./tools/testing/test.sh 30 bios $LOG_DIR 2>/dev/null; then
    echo "$1 - BIOS FAILED"
fi

if ! ./tools/testing/test.sh 30 uefi $LOG_DIR 2>/dev/null; then
    echo "$1 - UEFI FAILED"
fi

rm $PATCHED_KERNEL $LOG_DIR
