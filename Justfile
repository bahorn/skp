default:
  just --list

export BASEDIR := `pwd`

setup:
    virtualenv -p python3 .venv
    ./tools/setup.sh

run-ovmf :
    qemu-system-x86_64 \
        -accel kvm \
        -smbios type=0,uefi=on \
        -bios /usr/share/ovmf/OVMF.fd \
        -hda $ROOTFS \
        -m 4G \
        -kernel $PATCHED_KERNEL \
        -nographic \
        -gdb tcp::1234 \
        -S \
        -append "console=ttyS0,9600 root=/dev/sda" \
        -monitor tcp:127.0.0.1:55555,server,nowait \
        -netdev user,id=network0 -device e1000,netdev=network0,mac=52:54:00:12:34:56

run-bios:
    qemu-system-x86_64 \
        -accel kvm \
        -hda ${ROOTFS} \
        -m 4G \
        -kernel ${PATCHED_KERNEL} \
        -nographic \
        -gdb tcp::1234 \
        -S \
        -append "console=ttyS0,9600 root=/dev/sda" \
        -monitor tcp:127.0.0.1:55555,server,nowait \
        -netdev user,id=network0 -device e1000,netdev=network0,mac=52:54:00:12:34:56

build:
    mkdir -p ${BASEDIR}/intermediate/`shasum ${SOURCE_KERNEL} | cut -f 1 -d ' '`
    ./src/skp.sh \
        ${SOURCE_KERNEL} \
        ${PAYLOAD} \
        ${BASEDIR}/intermediate/`shasum ${SOURCE_KERNEL} | cut -f 1 -d ' '` \
        ${PATCHED_KERNEL}

clean:
    make -C ./src/runtime clean
    -rm -r ${BASEDIR}/intermediate
    -rm ${PATCHED_KERNEL}
