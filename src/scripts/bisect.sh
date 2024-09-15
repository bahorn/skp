#!/bin/bash
#
export LINUX_PATH=$1
export TYPE=$2
export TIMEOUT=30

/media/a/misc/git/tmpout-submissions/skp/tools/easylkb/easylkb.py \
    -p $LINUX_PATH \
    -cm \
    --kconfig ./configs/config-ubuntu-no-modules.kconfig

# patch the kernel
just patch-kernel \
    $LINUX_PATH/arch/x86/boot/bzImage \
    $PAYLOAD


cat << EOF | timeout $TIMEOUT bash
just extra_qemu="" run-$TYPE > /tmp/log.txt
EOF

# Need to checkout the log for several messages
python3 ./src/scripts/verify.py --bisect --invert /tmp/log.txt
exit $?
