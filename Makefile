PATCHED_KERNEL=./sample-kernels/patch-kernel.bzimage
SOURCE_KERNEL=./sample-kernels/vmlinuz-6.8.0-41-generic
SOURCE_KERNEL=/media/a/misc/git/tmpout-submissions/easylkb/kernel/linux-5.18/arch/x86/boot/bzImage
# SOURCE_KERNEL=./sample-kernels/vmlinuz-5.15.0-117-generic
# SOURCE_KERNEL=./sample-kernels/vmlinuz-5.15.0-119-generic
ROOTFS=./sample-kernels/openwrt-23.05.4-x86-64-generic-ext4-rootfs.img

PAYLOAD=`pwd`/../klude2/artifacts/main.bin

run-ovmf: build
	qemu-system-x86_64 \
		-accel kvm \
		-smbios type=0,uefi=on \
        -bios /usr/share/ovmf/OVMF.fd \
		-hda $(ROOTFS) \
		-m 4G \
		-kernel $(PATCHED_KERNEL) \
		-nographic \
		-gdb tcp::1234 \
		-S \
		-append "console=ttyS0,9600 root=/dev/sda" \
		-monitor tcp:127.0.0.1:55555,server,nowait \
		-netdev user,id=network0 -device e1000,netdev=network0,mac=52:54:00:12:34:56

run-ovmf-just:
	qemu-system-x86_64 \
		-accel kvm \
		-smbios type=0,uefi=on \
        -bios /usr/share/ovmf/OVMF.fd \
		-hda $(ROOTFS) \
		-m 4G \
		-kernel $(PATCHED_KERNEL) \
		-nographic \
		-gdb tcp::1234 \
		-append "console=ttyS0,9600 root=/dev/sda" \
		-monitor tcp:127.0.0.1:55555,server,nowait \
		-netdev user,id=network0 -device e1000,netdev=network0,mac=52:54:00:12:34:56

run-bios: build
	qemu-system-x86_64 \
		-accel kvm \
		-hda $(ROOTFS) \
		-m 4G \
		-kernel $(PATCHED_KERNEL) \
		-nographic \
		-gdb tcp::1234 \
		-S \
		-append "console=ttyS0,9600 root=/dev/sda" \
		-monitor tcp:127.0.0.1:55555,server,nowait \
		-netdev user,id=network0 -device e1000,netdev=network0,mac=52:54:00:12:34:56

build: clean
	mkdir ./intermediate
	./src/skp.sh \
		$(SOURCE_KERNEL) $(PAYLOAD) `pwd`/intermediate $(PATCHED_KERNEL)

clean:
	make -C ./src/runtime/ clean
	-rm -r ./intermediate/
	-rm $(PATCHED_KERNEL)


setup:
	virtualenv -p python3 .venv
	./tools/setup.sh
