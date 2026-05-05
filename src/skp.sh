#!/bin/bash

SOURCE_KERNEL=$1
INTERMEDIATE=$2
PATCHED_KERNEL=$3
PAYLOAD=$4

echo $PAYLOAD

source .venv/bin/activate

# extract kallsyms
if [ ! -f $INTERMEDIATE/kallsyms ]; then
    uv run --project tools/vmlinux-to-elf kallsyms-finder $SOURCE_KERNEL > $INTERMEDIATE/kallsyms
fi

# extract the kernel so we can find an offset to copy out payload to in the
# kernel image.
if [ ! -f $INTERMEDIATE/curr.elf ]; then
    uv tool run tools/vmlinux-to-elf \
        $SOURCE_KERNEL \
        $INTERMEDIATE/curr.elf
fi

echo $INTERMEDIATE

# Patch the kernel image to install the payload
python3 src/patch-bzimage patch \
    $SOURCE_KERNEL \
    $INTERMEDIATE/curr.elf \
    $INTERMEDIATE/kallsyms \
    ./src/runtime/combined.o \
    ./src/runtime/linker.lds \
    $PATCHED_KERNEL \
    $PAYLOAD \
    $EXTRA_PATCH
