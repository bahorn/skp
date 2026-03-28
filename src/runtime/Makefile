
build:
	PAYLOAD=$(PAYLOAD) make -C kshelf-loader
	SYMBOLS=$(SYMBOLS) LOAD_OFFSET=$(LOAD_OFFSET) make -C ./stage2
	SYMBOLS=$(SYMBOLS) LOAD_OFFSET=$(LOAD_OFFSET) \
			make -C ./stage1-uefi-bootservices-hook
	make -C ./stage0/
	ld -T./linker.lds \
		 -Map=output.map \
		./stage0/stage0.o \
		./stage1-uefi-bootservices-hook/stage1.o \
		./stage2/stage2.o \
		-o all.bin

clean:
	-rm all.bin payload.h output.map
	make -C ./stage0/ clean
	make -C ./kshelf-loader/ clean
	make -C ./stage2 clean
	make -C ./stage1-uefi-bootservices-hook clean
