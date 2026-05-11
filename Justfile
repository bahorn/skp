# These can be overridden!
BASEDIR := shell("pwd")
INTERMEDIATE := BASEDIR / "intermediate"
ovmffw := env("OVMFFW", "/usr/share/OVMF/OVMF_CODE_4M.fd")
rootfs := env("ROOTFS", BASEDIR / "samples/rootfs/openwrt-rootfs.img")
patched_kernel := env("PATCHED_KERNEL", BASEDIR / "samples/patched-kernel.bzimage")
grub_root := env("GRUB_ROOT", BASEDIR / "samples/grub-root")
config_dir := BASEDIR / "configs"
default_payload := BASEDIR / "tools/klude2/samples/nop"
# Having the debuging features here so it can be easily turned off in the
# testing scripts, allowing them to be parallel.
extra_qemu := "-monitor tcp:127.0.0.1:55555,server,nowait" + \
    " -gdb tcp::1234" + \
    " -netdev user,id=network0" + \
    " -device e1000,netdev=network0,mac=52:54:00:12:34:56"
skip_build_runtime := "false"
# We have a unique id we generate each run of the justfile so that we can run
# instances of a few of the commands that need files in parallel
run_id := `uuidgen`

# Extra flags to patch-bzimage, can disable uefi or bios patching with this.
export EXTRA_PATCH := env("EXTRA_PATCH", "")

# Nothing currently
export EXTRA_STAGE2_DEFINE := env("EXTRA_STAGE2_DEFINE", "")

# List Commands
[group('Listing')]
default:
  just --list

# Install dependencies to build the project
[group('setup')]
setup:
    virtualenv -p python3 .venv
    ./tools/setup.sh
    just -f ./tools/klude2/ custom custom

# Run a Kernel via UEFI with OVMF
[group('run')]
run-uefi:
    python3 tools/memfd_serve.py ovmf_vars-{{run_id}} \
        /usr/share/OVMF/OVMF_VARS_4M.fd &
    python3 tools/memfd_serve.py rootfs-{{run_id}} \
        {{rootfs}} &
    qemu-system-x86_64 \
        -accel kvm \
        -m 4G \
        -kernel {{patched_kernel}} \
        -nographic \
        -append "console=ttyS0,9600 root=/dev/vda" \
        -drive file=`./tools/mff.sh rootfs-{{run_id}}`,format=raw,if=virtio,index=0 \
        -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
        -drive if=pflash,format=raw,file=`./tools/mff.sh ovmf_vars-{{run_id}}` \
        {{extra_qemu}}

# Run a Kernel via BIOS
[group('run')]
run-bios:
    python3 tools/memfd_serve.py rootfs-{{run_id}} \
        {{rootfs}} &
    qemu-system-x86_64 \
        -accel kvm \
        -hda `./tools/mff.sh rootfs-{{run_id}}` \
        -m 4G \
        -kernel {{patched_kernel}} \
        -nographic \
        -append "console=ttyS0,9600 root=/dev/sda" \
        {{extra_qemu}}

# Run the Kernel via UEFI GRUB -  *Can not be ran in parallel!*
[group('run')]
run-grub-uefi:
    -rm -r {{grub_root}}
    mkdir -p {{grub_root}}/EFI/boot {{grub_root}}/EFI/ubuntu
    cp ./samples/grub/grubx64.efi {{grub_root}}/EFI/boot/bootx64.efi
    cp {{patched_kernel}} {{grub_root}}/kernel.bzimage
    cp {{config_dir}}/grub-uefi.cfg {{grub_root}}/EFI/ubuntu/grub.cfg
    cp /usr/share/OVMF/OVMF_VARS_4M.fd `pwd`/tmp/OVMF_VARS_4M.fd

    qemu-system-x86_64 \
        -accel kvm \
        -m 4G \
        -nographic \
        -drive file=fat:rw:samples/grub-root,if=ide,index=0 \
        -drive file={{rootfs}},format=raw,if=virtio \
        -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
        -drive if=pflash,format=raw,file=`pwd`/tmp/OVMF_VARS_4M.fd \
        {{extra_qemu}}

# Run the kernel via a BIOS grub rescue images - *Can not be ran in parallel!*
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
        {{extra_qemu}}

# Patch a kernel
[group('build')]
patch-kernel kernel=env("SOURCE_KERNEL") output=patched_kernel payload=env("PAYLOAD", ""):
    mkdir -p {{INTERMEDIATE}}/`./tools/shasum.sh {{kernel}}`

    # compile the runtime.
    # This is kernel agnostic and works across them, with the payload only
    # linked later on.
    {{ if skip_build_runtime != "true" { "make -C ./src/runtime" } else { "" } }}

    ./src/skp.sh \
        {{kernel}} \
        {{INTERMEDIATE}}/`./tools/shasum.sh {{kernel}}` \
        {{output}} \
        {{ if payload != "" { "--payload=" + payload } else { "" } }}

# Patch a kernel based on the source tree provide, and build a payload for it from source.
[group('build')]
patch-with-payload path payload=default_payload:
    make -C ./src/runtime
    just -f ./tools/klude2/Justfile clean
    # using realpath to take relative paths!
    just -f ./tools/klude2/Justfile build-path \
        `realpath {{path}}` `realpath {{payload}}`
    shasum ./tools/klude2/artifacts/pl.o
    readelf -a ./tools/klude2/artifacts/pl.o
    just patch-kernel {{path}}/arch/x86/boot/bzImage {{patched_kernel}} \
        ./tools/klude2/artifacts/pl.o
    shasum ./tools/klude2/artifacts/pl.o

# Download OpenWRTs rootfs
[group('setup')]
get-rootfs:
    mkdir -p samples/rootfs/
    wget -O samples/rootfs/openwrt-rootfs.img.gz \
        https://downloads.openwrt.org/releases/23.05.4/targets/x86/64/openwrt-23.05.4-x86-64-generic-ext4-rootfs.img.gz
    cd samples/rootfs/ && gunzip openwrt-rootfs.img.gz

# Download the Ubuntu's UEFI build of GRUB
[group('setup')]
get-grub-uefi:
    mkdir -p samples/grub/
    wget -O samples/grub/grub-ubuntu.deb http://launchpadlibrarian.net/817183946/grub-efi-amd64-unsigned_2.14~git20250718.0e36779-1ubuntu4_amd64.deb
    cd ./samples/grub/ && \
        ar x ./grub-ubuntu.deb && \
        tar -xf ./data.tar.xz && \
        cp ./usr/lib/grub/x86_64-efi/monolithic/grubx64.efi grubx64.efi && \
        rm -r control.tar.xz data.tar.xz debian-binary ./usr

# Use easylkb to build a kernel
[group('setup')]
easylkb version kconfig=(BASEDIR / "configs/test.KConfig") extra="":
    cd ./tools/easylkb/ && \
        python3 easylkb.py -k {{version}} --kconfig {{kconfig}} -dcm {{ extra }}

# Clean the Project
[group('build')]
clean:
    make -C ./src/runtime clean
    -rm -r {{INTERMEDIATE}}
    -rm {{patched_kernel}}
    -rm -r {{grub_root}}

# Test a list of kernels. This does not rebuild the payload for the given kernel.
[group('testing')]
test-batch test_kernel_list payload=env("PAYLOAD", ""):
    make -C ./src/runtime
    cat {{test_kernel_list}} | \
        parallel -j 4 -I HERE ./tools/testing/test-batch.sh HERE {{payload}}

# End to end testing of a kernel tree, building the payload from source.
[group('testing')]
end-to-end path payload=default_payload:
    {{ if skip_build_runtime != "true" { "make -C ./src/runtime" } else { "" } }}
    # using realpath to take relative paths!
    just -f ./tools/klude2/Justfile clean
    just -f ./tools/klude2/Justfile build-path \
        `realpath {{path}}` `realpath {{payload}}`
    ./tools/testing/test-batch.sh \
        {{path}}/arch/x86/boot/bzImage ./tools/klude2/artifacts/pl.o

[group('testing')]
end-to-end-batch test_kernel_list payload=default_payload:
    make -C ./src/runtime
    cat {{test_kernel_list}} | \
        xargs -I HERE just --set skip_build_runtime true end-to-end HERE {{ payload }}

# Connect to the GDB server
[group('run')]
gdb:
    gdb -ex "target remote localhost:1234"

[group('dev')]
lint:
    uvx ruff check ./src/patch-bzimage/
