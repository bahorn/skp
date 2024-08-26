OUT=stage1.bin
CFLAGS=-S \
	   -O0 \
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

build: stage1.bin

src/entry.s:
	$(CC) -o src/entry.s $(CFLAGS) src/entry.c

src/main.s:
	$(CC) -o src/main.s $(CFLAGS) src/main.c

src/entry.o: src/entry.s
	$(AS) $(ASFLAGS) -o src/entry.o src/entry.s

src/main.o: src/main.s
	$(AS) $(ASFLAGS) -o src/main.o src/main.s

$(OUT): src/entry.o src/main.o
	mkdir -p generated
	python3 ./scripts/symbol_offsets.py $(SYMBOLS) > generated/offsets.lds
	echo LOAD_OFFSET = $(LOAD_OFFSET)\; > generated/load.lds
	$(LD) -o $(OUT) $(LDFLAGS) src/*.o

clean:
	-rm src/*.o src/*.s $(OUT)
