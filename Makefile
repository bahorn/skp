PATCHED_KERNEL=./sample-kernels/out2
SOURCE_KERNEL=./sample-kernels/vmlinuz-6.8.0-40-generic
#SOURCE_KERNEL=./sample-kernels/vmlinuz-5.15.0-117-generic
#SOURCE_KERNEL=/media/a/misc/git/tmpout-submissions/skp/sample-kernels/arch/usr/lib/modules/6.10.6-arch1-1/vmlinuz
ROOTFS=./sample-kernels/openwrt-23.05.4-x86-64-generic-ext4-rootfs.img

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
	make -C ./payload/stage1/ clean
	# extract kallsyms
	# Find space we can copy our payload to in the kernel image
	# compile the payload
	SYMBOLS=`pwd`/sample-kernels/kallsyms make -C ./payload/stage1/
	SYMBOLS=`pwd`/sample-kernels/kallsyms make -C ./payload/stage0/
	cat ./payload/stage0/stage0.bin ./payload/stage1/stage1.bin > ./payload/all.bin

	# Patch the kernel image to install the payload
	python3 src $(SOURCE_KERNEL) $(PATCHED_KERNEL)
