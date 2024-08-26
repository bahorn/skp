PATCHED_KERNEL=./sample-kernels/out2
SOURCE_KERNEL=`pwd`/sample-kernels/vmlinuz-6.8.0-40-generic
ROOTFS=./sample-kernels/openwrt-23.05.4-x86-64-generic-ext4-rootfs.img

PAYLOAD=../klude2/artifacts/main.bin

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

build:
	# cleaning
	make -C ./payload/ clean
	# extract kallsyms
	# extract the kernel so we can find an offset to copy out payload to in the
	# kernel image.
	./tools/extract-vmlinux $(SOURCE_KERNEL) > ./sample-kernels/curr.elf

	# compile the payload
	PAYLOAD=$(SOURCE_KERNEL) \
		SYMBOLS=`pwd`/sample-kernels/kallsyms \
		LOAD_OFFSET=0x01320000 \
		make -C ./payload/

	# Patch the kernel image to install the payload
	python3 src $(SOURCE_KERNEL) $(PATCHED_KERNEL)
