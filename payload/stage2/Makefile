build:
	nasm \
		-D __efi_call=`python3 ../../src/scripts/find_symbol.py $(SYMBOLS) __efi_call` \
		-D _stage1_offset=$(LOAD_OFFSET) \
		-D _startup_64_offset=`python3 ../../src/scripts/find_symbol.py $(SYMBOLS) startup_64` \
		-D runtime_hook_len=`wc -c < ../kshelf-loader/runtime_hook.bin` \
		-D _initcall_offset=`python3 ../../src/scripts/find_initcall.py $(SYMBOLS)` \
		-f bin ./thunk.asm \
		-o thunk.bin

	cat ./thunk.bin ../kshelf-loader/runtime_hook.bin > runtime.bin
	xxd -i runtime.bin > runtime.h

clean:
	-rm thunk.bin runtime.h runtime.bin
