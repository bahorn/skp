CFLAGS=-fPIE -fno-builtin -nostdlib -fno-plt -fno-common -O0 -I/usr/include/efi -mabi=ms
LDFLAGS=-T./linker.lds -pie

build:
	$(CC) \
		$(EXTRA_STAGE2_DEFINE) \
		$(CFLAGS) \
		-c main.c -o main.o
	objcopy --prefix-sections=.stage1 main.o stage1.o


clean:
	-rm main.o stage1.o
