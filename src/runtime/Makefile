
build:
	PAYLOAD=$(PAYLOAD) make -C kshelf-loader
	SYMBOLS=$(SYMBOLS) LOAD_OFFSET=$(LOAD_OFFSET) make -C ./stage2
	SYMBOLS=$(SYMBOLS) LOAD_OFFSET=$(LOAD_OFFSET) \
			make -C ./stage1-uefi-bootservices-hook
	make -C ./stage0/
	ld -T./linker.lds ./stage0/stage0.o -o all.bin
	python3 fill_in.py ./all.bin


clean:
	-rm all.bin payload.h
	make -C ./stage0/ clean
	make -C ./kshelf-loader/ clean
	make -C ./stage2 clean
	make -C ./stage1-uefi-bootservices-hook clean
