
build:
	../tools/xxd.py $(PAYLOAD) payload > ./payload.h
	SYMBOLS=$(SYMBOLS) make -C stage2-kshelf-loader
	SYMBOLS=$(SYMBOLS) LOAD_OFFSET=$(LOAD_OFFSET) make -C ./stage1-uefi-bootservices-hook
	SYMBOLS=$(SYMBOLS) LOAD_OFFSET=$(LOAD_OFFSET) \
			make -C ./stage0/
	cat ./stage0/stage0.bin ./stage1-uefi-bootservices-hook/bootservices_hook.bin > ./all.bin
	python3 fill_in.py ./all.bin


clean:
	-rm all.bin payload.h
	make -C ./stage0/ clean
	make -C ./stage2-kshelf-loader/ clean
	make -C ./stage1-uefi-bootservices-hook clean
