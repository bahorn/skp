#!/bin/bash

SOURCE_KERNEL=$1
INTERMEDIATE=$2
PATCHED_KERNEL=$3

echo $PAYLOAD

source .venv/bin/activate

# extract kallsyms
if [ ! -f $INTERMEDIATE/kallsyms ]; then
    kallsyms-finder $SOURCE_KERNEL > $INTERMEDIATE/kallsyms
fi

# extract the kernel so we can find an offset to copy out payload to in the
# kernel image.
if [ ! -f $INTERMEDIATE/curr.elf ]; then
    ./tools/extract-vmlinux $SOURCE_KERNEL > $INTERMEDIATE/curr.elf
fi

# compile the runtime.
# This takes another environment variable called payload, but we do not pass it
# directly in.
SYMBOLS=$INTERMEDIATE/kallsyms \
    LOAD_OFFSET=`python3 ./src/scripts/find_space.py $INTERMEDIATE/curr.elf` \
    make -C ./src/runtime

cp ./src/runtime/all.bin $INTERMEDIATE/runtime.bin


# Patch the kernel image to install the payload
python3 src/patch-bzimage \
    $SOURCE_KERNEL \
    $INTERMEDIATE/runtime.bin \
    $PATCHED_KERNEL \
    $EXTRA_PATCH
