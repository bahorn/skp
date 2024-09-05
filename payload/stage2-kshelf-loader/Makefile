CFLAGS=-O0 \
	   -fPIE \
	   -fno-builtin \
	   -nostdlib \
	   -nolibc \
	   -DCONFIG_X86_X32_ABI \
	   -DMODULE \
	   -D__KERNEL__ \
	   -Wall \
	   -Wundef \
	   -Werror=strict-prototypes \
	   -Wno-trigraphs \
	   -fno-strict-aliasing \
	   -fno-common \
	   -fshort-wchar \
	   -Werror=implicit-function-declaration \
	   -Werror=implicit-int \
	   -Werror=return-type \
	   -Wno-format-security \
	   -std=gnu99 \
	   -mno-sse \
	   -mno-mmx \
	   -mno-sse2 \
	   -mno-3dnow \
	   -mno-avx \
	   -m64 \
	   -falign-jumps=1 \
	   -falign-loops=1 \
	   -mno-80387 \
	   -mno-fp-ret-in-387 \
	   -mpreferred-stack-boundary=3 \
	   -mskip-rax-setup \
	   -mtune=generic \
	   -mno-red-zone \
	   -Wno-sign-compare \
	   -fno-asynchronous-unwind-tables \
	   -fno-jump-tables \
	   -mharden-sls=all \
	   -fno-delete-null-pointer-checks \
	   -Wno-frame-address \
	   -Wno-format-truncation \
	   -Wno-format-overflow \
	   -Wno-address-of-packed-member \
	   -fno-allow-store-data-races \
	   -Wframe-larger-than=1024 \
	   -fstack-protector-strong \
	   -Wimplicit-fallthrough=5 \
	   -Wno-main \
	   -Wno-unused-but-set-variable \
	   -Wno-unused-const-variable \
	   -fno-omit-frame-pointer \
	   -fno-optimize-sibling-calls \
	   -fno-stack-clash-protection \
	   -mrecord-mcount \
	   -mfentry \
	   -DCC_USING_FENTRY \
	   -Wdeclaration-after-statement \
	   -Wvla \
	   -Wno-pointer-sign \
	   -Wno-stringop-truncation \
	   -Wno-zero-length-bounds \
	   -Wno-array-bounds \
	   -Wno-stringop-overflow \
	   -Wno-restrict \
	   -Wno-maybe-uninitialized \
	   -Wno-alloc-size-larger-than \
	   -fno-strict-overflow \
	   -fno-stack-check \
	   -fconserve-stack \
	   -Werror=date-time \
	   -Werror=incompatible-pointer-types \
	   -Werror=designated-init \
	   -Wno-packed-not-aligned \
	   -fsanitize=bounds \
	   -fsanitize=shift \
	   -fsanitize=bool \
	   -fsanitize=enum
ASFLAGS=--64
LDFLAGS=-T ./linker.lds -pie

CC=gcc
LD=ld


build:
	$(CC) \
		$(CFLAGS) \
		-D KALLSYMS_OFFSET=`python3 ../../src/find_symbol.py $(SYMBOLS) kallsyms_lookup_name` \
		-c ./src/entry.c -o main.o
	$(LD) $(LDFLAGS) ./main.o -o runtime_hook.bin

	nasm \
		-D __efi_call=`python3 ../../src/find_symbol.py $(SYMBOLS) __efi_call` \
		-D _stage1_offset=$(LOAD_OFFSET) \
		-D _startup_64_offset=`python3 ../../src/find_symbol.py $(SYMBOLS) startup_64` \
		-D runtime_hook_len=`wc -c < ./runtime_hook.bin` \
		-D _initcall_offset=`python3 ../../src/find_initcall.py $(SYMBOLS)` \
		-f bin ./thunk.asm \
		-o thunk.bin
	cat ./thunk.bin ./runtime_hook.bin > runtime.bin
	xxd -i runtime.bin > runtime.h

clean:
	-rm thunk.bin runtime.h main.o runtime_hook.bin runtime.bin
