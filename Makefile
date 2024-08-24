PATCHED_KERNEL=./sample-kernels/out2
SOURCE_KERNEL=./sample-kernels/vmlinuz-6.8.0-40-generic
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


run-ovmf-2:
	qemu-system-x86_64 \
		-accel kvm \
		-smbios type=0,uefi=on \
        -bios /usr/share/ovmf/OVMF.fd \
		-hda $(ROOTFS) \
		-m 4G \
		-kernel ./sample-kernels/removed.kernel \
		-nographic \
		-gdb tcp::1234 \
		-S \
		-append "console=ttyS0,9600 root=/dev/sda" \
		-monitor tcp:127.0.0.1:55555,server,nowait \
		-netdev user,id=network0 -device e1000,netdev=network0,mac=52:54:00:12:34:56


build:
	make -C ./payload/stage1/ clean
	SYMBOLS=`pwd`/sample-kernels/kallsyms make -C ./payload/stage1/
	make -C ./payload/stage0/
	cat ./payload/stage0/stage0.bin ./payload/stage1/stage1.bin > ./payload/all.bin
	python3 src $(SOURCE_KERNEL) $(PATCHED_KERNEL)
