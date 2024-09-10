#!/bin/bash

export SOURCE_KERNEL=$1
export REAL_PAYLOAD=$2
export INTERMEDIATE=$3
export PATCHED_KERNEL=$4
# extract kallsyms
kallsyms-finder $SOURCE_KERNEL > $INTERMEDIATE/kallsyms

# extract the kernel so we can find an offset to copy out payload to in the
# kernel image.
./tools/extract-vmlinux $SOURCE_KERNEL > $INTERMEDIATE/curr.elf

# compile the payload
PAYLOAD=$REAL_PAYLOAD \
    SYMBOLS=$INTERMEDIATE/kallsyms \
    LOAD_OFFSET=`python3 ./src/scripts/find_space.py $INTERMEDIATE/curr.elf` \
    make -C ./src/runtime

cp ./src/runtime/all.bin $INTERMEDIATE/runtime.bin

# Patch the kernel image to install the payload
python3 src/patch-bzimage \
    $SOURCE_KERNEL \
    $INTERMEDIATE/runtime.bin \
    $PATCHED_KERNEL
