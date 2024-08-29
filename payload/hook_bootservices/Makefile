CFLAGS=-fPIE -fno-builtin -nostdlib -fno-plt -O2 -I/usr/include/efi -mabi=ms
LDFLAGS=-T./linker.lds -pie

build:
	$(CC) $(CFLAGS) -c main.c -o main.o
	$(LD) $(LDFLAGS) ./main.o -o bootservices_hook.bin


clean:
	-rm main.o bootservices_hook.bin

