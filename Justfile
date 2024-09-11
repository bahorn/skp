# List Commands
default:
  just --list

# These can be overridden!
BASEDIR := shell("pwd")
INTERMEDIATE := BASEDIR / "intermediate"
ovmffw := env("OVMFFW", "/usr/share/ovmf/OVMF.fd")
rootfs := env("ROOTFS", BASEDIR / "sample-kernels/openwrt-rootfs.img")
patched_kernel := env("PATCHED_KERNEL", BASEDIR / "sample-kernels/patched-kernel.bzimage")

# Install dependencies to build the project
setup:
    virtualenv -p python3 .venv
    ./tools/setup.sh

# Run a Kernel via UEFI with OVMF
run-ovmf :
    qemu-system-x86_64 \
        -accel kvm \
        -hda {{rootfs}} \
        -m 4G \
        -kernel {{patched_kernel}} \
        -nographic \
        -gdb tcp::1234 \
        -S \
        -append "console=ttyS0,9600 root=/dev/sda" \
        -monitor tcp:127.0.0.1:55555,server,nowait \
        -netdev user,id=network0 \
        -device e1000,netdev=network0,mac=52:54:00:12:34:56 \
        -smbios type=0,uefi=on \
        -bios {{ovmffw}}

# Run a Kernel via BIOS
run-bios:
    qemu-system-x86_64 \
        -accel kvm \
        -hda {{rootfs}} \
        -m 4G \
        -kernel {{patched_kernel}} \
        -nographic \
        -gdb tcp::1234 \
        -S \
        -append "console=ttyS0,9600 root=/dev/sda" \
        -monitor tcp:127.0.0.1:55555,server,nowait \
        -netdev user,id=network0 \
        -device e1000,netdev=network0,mac=52:54:00:12:34:56

# Patch a kernel
patch-kernel kernel=env("SOURCE_KERNEL") payload=env("PAYLOAD"):
    mkdir -p {{INTERMEDIATE}}/`./tools/shasum.sh {{kernel}}`
    ./src/skp.sh \
        {{kernel}} \
        {{payload}} \
        {{INTERMEDIATE}}/`./tools/shasum.sh {{kernel}}` \
        {{patched_kernel}}

# Download OpenWRTs rootfs
get-rootfs:
    wget -O sample-kernels/openwrt-rootfs.img.gz \
        https://downloads.openwrt.org/releases/23.05.4/targets/x86/64/openwrt-23.05.4-x86-64-generic-ext4-rootfs.img.gz
    cd sample-kernels && gunzip openwrt-rootfs.img.gz

# Clean the Project
clean:
    make -C ./src/runtime clean
    -rm -r {{INTERMEDIATE}}
    -rm {{patched_kernel}}
