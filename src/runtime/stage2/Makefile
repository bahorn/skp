build:
	nasm \
		-D __efi_call=`python3 ../../scripts/find_symbol.py $(SYMBOLS) __efi_call` \
		-D _stage1_offset=$(LOAD_OFFSET) \
		-D _startup_64_offset=`python3 ../../scripts/find_symbol.py $(SYMBOLS) startup_64` \
		-D _initcall_offset=`python3 ../../scripts/find_initcall.py $(SYMBOLS)` \
		-D __preempt_count=`python3 ../../scripts/find_preempt_count.py $(SYMBOLS)` \
		-f elf64 ./stage2.asm \
		-o stage2.o

clean:
	-rm stage2.o
