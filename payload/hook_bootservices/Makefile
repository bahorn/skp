CFLAGS=-fPIE -fno-builtin -nostdlib -fno-plt -O0 -I/usr/include/efi -mabi=ms
LDFLAGS=-T./linker.lds -pie

build:
	$(CC) \
		-D _initcall_offset=`python3 ../../src/find_initcall.py $(SYMBOLS)` \
		-DLOAD_OFFSET=$(LOAD_OFFSET) \
		$(CFLAGS) \
		-c main.c -o main.o
	$(LD) $(LDFLAGS) ./main.o -o bootservices_hook.bin


clean:
	-rm main.o bootservices_hook.bin

