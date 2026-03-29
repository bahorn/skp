build:
	nasm \
		-D __preempt_count=`python3 ../../scripts/find_preempt_count.py $(SYMBOLS)` \
		-f elf64 ./stage2.asm \
		-o stage2.o
	objcopy --prefix-sections=.stage2 stage2.o stage2.o

clean:
	-rm stage2.o
