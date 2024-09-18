# These can be overridden!
BASEDIR := shell("pwd")
INTERMEDIATE := BASEDIR / "intermediate"
ovmffw := env("OVMFFW", "/usr/share/OVMF/OVMF_CODE.fd")
rootfs := env("ROOTFS", BASEDIR / "samples/rootfs/openwrt-rootfs.img")
patched_kernel := env("PATCHED_KERNEL", BASEDIR / "samples/patched-kernel.bzimage")
grub_root := env("GRUB_ROOT", BASEDIR / "samples/grub-root")
config_dir := BASEDIR / "configs"
extra_qemu := "-S"
kernel_cmdline := "\"console=ttyS0,9600 root=/dev/sda\""

# Extra flags to patch-bzimage, can disable uefi or bios patching with this.
export EXTRA_PATCH := env("EXTRA_PATCH", "")

# To enable / disable direct patching
export EXTRA_STAGE2_DEFINE := env("EXTRA_STAGE2_DEFINE", "-DDIRECT_PATCHING")

# List Commands
[group('Listing')]
default:
  just --list

# Install dependencies to build the project
[group('setup')]
setup:
    virtualenv -p python3 .venv
    ./tools/setup.sh

# Run a Kernel via UEFI with OVMF
[group('run')]
run-uefi :
    qemu-system-x86_64 \
        -accel kvm \
        -hda {{rootfs}} \
        -m 4G \
        -kernel {{patched_kernel}} \
        -nographic \
        -gdb tcp::1234 \
        -append {{kernel_cmdline}} \
        -monitor tcp:127.0.0.1:55555,server,nowait \
        -netdev user,id=network0 \
        -device e1000,netdev=network0,mac=52:54:00:12:34:56 \
        -smbios type=0,uefi=on \
        -bios {{ovmffw}} \
        {{extra_qemu}}

# Run a Kernel via BIOS
[group('run')]
run-bios:
    qemu-system-x86_64 \
        -accel kvm \
        -hda {{rootfs}} \
        -m 4G \
        -kernel {{patched_kernel}} \
        -nographic \
        -gdb tcp::1234 \
        -append {{kernel_cmdline}} \
        -monitor tcp:127.0.0.1:55555,server,nowait \
        -netdev user,id=network0 \
        -device e1000,netdev=network0,mac=52:54:00:12:34:56 \
        {{extra_qemu}}

# Run the Kernel via UEFI GRUB
[group('run')]
run-grub-uefi:
    -rm -r {{grub_root}}
    mkdir -p {{grub_root}}/efi/boot {{grub_root}}/EFI/ubuntu
    cp ./samples/grub/grubx64.efi {{grub_root}}/efi/boot/bootx64.efi
    cp {{patched_kernel}} {{grub_root}}/kernel.bzimage
    cp {{config_dir}}/grub-uefi.cfg {{grub_root}}/EFI/ubuntu/grub.cfg

    qemu-system-x86_64 \
        -hda fat:rw:samples/grub-root \
        -hdb {{rootfs}} \
        -accel kvm \
        -m 4G \
        -nographic \
        -gdb tcp::1234 \
        -monitor tcp:127.0.0.1:55555,server,nowait \
        -netdev user,id=network0 \
        -device e1000,netdev=network0,mac=52:54:00:12:34:56 \
        -smbios type=0,uefi=on \
        -bios {{ovmffw}} \
        {{extra_qemu}}

# Run the kernel via a BIOS grub rescue imagea
[group('run')]
run-grub-bios:
    -rm -r {{grub_root}}
    mkdir -p {{grub_root}}/boot/grub
    cp {{patched_kernel}} {{grub_root}}/kernel.bzimage
    cp {{config_dir}}/grub-bios.cfg {{grub_root}}/boot/grub/grub.cfg
    grub-mkrescue -o ./samples/grub.iso {{grub_root}}

    qemu-system-x86_64 \
        -hda ./samples/grub.iso \
        -hdb {{rootfs}} \
        -accel kvm \
        -m 4G \
        -nographic \
        -gdb tcp::1234 \
        -S \
        -monitor tcp:127.0.0.1:55555,server,nowait \
        -netdev user,id=network0 \
        -device e1000,netdev=network0,mac=52:54:00:12:34:56 \
        {{extra_qemu}}

# Patch a kernel
[group('build')]
patch-kernel kernel=env("SOURCE_KERNEL") payload=env("PAYLOAD"):
    mkdir -p {{INTERMEDIATE}}/`./tools/shasum.sh {{kernel}}`
    ./src/skp.sh \
        {{kernel}} \
        {{payload}} \
        {{INTERMEDIATE}}/`./tools/shasum.sh {{kernel}}` \
        {{patched_kernel}}

# Download OpenWRTs rootfs
[group('setup')]
get-rootfs:
    wget -O samples/rootfs/openwrt-rootfs.img.gz \
        https://downloads.openwrt.org/releases/23.05.4/targets/x86/64/openwrt-23.05.4-x86-64-generic-ext4-rootfs.img.gz
    cd samples/rootfs/ && gunzip openwrt-rootfs.img.gz

# Download the Ubuntu's UEFI build of GRUB
[group('setup')]
get-grub-uefi:
    mkdir -p samples/grub/
    wget -O samples/grub/grub-ubuntu.deb https://launchpad.net/ubuntu/+archive/primary/+files/grub-efi-amd64-unsigned_2.12-5ubuntu4_amd64.deb
    cd ./samples/grub/ && \
        ar x ./grub-ubuntu.deb && \
        tar -xf ./data.tar.xz && \
        cp ./usr/lib/grub/x86_64-efi/monolithic/grubx64.efi grubx64.efi && \
        rm -r control.tar.xz data.tar.xz debian-binary ./usr

# Use easylkb to build a kernel
[group('setup')]
easylkb version kconfig=(BASEDIR / "configs/test.KConfig"):
    cd ./tools/easylkb/ && python3 easylkb.py -k {{version}} --kconfig {{kconfig}} -dcm 

# Clean the Project
[group('build')]
clean:
    make -C ./src/runtime clean
    -rm -r {{INTERMEDIATE}}
    -rm {{patched_kernel}}
    -rm -r {{grub_root}}

# Test a list of kernels
[group('testing')]
test-batch test_kernel_list payload=env("PAYLOAD"):
    cat {{test_kernel_list}} | xargs -I HERE ./src/scripts/test-batch.sh HERE {{payload}}

# Connect to the GDB server
[group('run')]
gdb:
    gdb -ex "target remote localhost:1234"
