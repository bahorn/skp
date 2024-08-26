build:
	nasm \
		-D _stage1_offset=$(LOAD_OFFSET)\
		-D _initcall_offset=`python3 ../../src/find_initcall.py $(SYMBOLS)` \
		-D stage1_len=`wc -c < ../stage1/stage1.bin` \
		-f bin \
		-o stage0.bin \
		./stage0.asm

clean:
	-rm ./stage0.bin
