#!/bin/bash
#
export LINUX_PATH=$1
export TYPE=$2
export TIMEOUT=30

rm $LINUX_PATH/.config $LINUXPATH/.config.old $LINUX_PATH.config

./tools/easylkb/easylkb.py \
    -p $LINUX_PATH/ \
    --kconfig `pwd`/configs/config-ubuntu-no-modules.kconfig \
    -cm

# clean else we'll have 10gigs of kernel elfs, and makes checking for the
# patched kernel easier
just clean

# patch the kernel
just patch-kernel \
    $LINUX_PATH/arch/x86/boot/bzImage \
    $PAYLOAD

# if the patched_kernel does not exist, it did not build correctly.
if [ ! -f ./samples/patched-kernel.bzimage ]; then
    exit -1
fi

cat << EOF | timeout $TIMEOUT bash
just extra_qemu="" run-$TYPE > /tmp/log.txt
EOF

# Need to checkout the log for several messages
python3 ./src/scripts/verify.py --bisect --invert /tmp/log.txt
exit $?
