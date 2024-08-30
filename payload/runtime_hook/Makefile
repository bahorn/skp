CFLAGS=-fPIE -fno-builtin -nostdlib -fno-plt -O0
LDFLAGS=-T./linker.lds -pie

build:
	$(CC) \
		$(CFLAGS) \
		-D PRINTK_OFFSET=`python3 ../../src/find_symbol.py $(SYMBOLS) _printk` \
		-c main.c -o main.o
	$(LD) $(LDFLAGS) ./main.o -o runtime_hook.bin
	nasm -D __efi_call=`python3 ../../src/find_symbol.py $(SYMBOLS) __efi_call` \
		-f bin thunk.asm -o thunk.bin
	cat ./thunk.bin ./runtime_hook.bin > runtime.bin
	xxd -i runtime.bin > runtime.h

clean:
	-rm thunk.bin runtime.h main.o runtime_hook.bin runtime.bin
