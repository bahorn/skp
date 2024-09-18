
build:
ifdef PAYLOAD
	../../tools/xxd.py $(PAYLOAD) payload > ./payload.h
	SYMBOLS=$(SYMBOLS) PAYLOAD=-DPAYLOAD make -C kshelf-loader
else
	SYMBOLS=$(SYMBOLS) make -C kshelf-loader
endif
	SYMBOLS=$(SYMBOLS) LOAD_OFFSET=$(LOAD_OFFSET) make -C ./stage2
	SYMBOLS=$(SYMBOLS) LOAD_OFFSET=$(LOAD_OFFSET) \
			make -C ./stage1-uefi-bootservices-hook
	SYMBOLS=$(SYMBOLS) LOAD_OFFSET=$(LOAD_OFFSET) \
			make -C ./stage0/
	cp ./stage0/stage0.bin ./all.bin
	python3 fill_in.py ./all.bin


clean:
	-rm all.bin payload.h
	make -C ./stage0/ clean
	make -C ./kshelf-loader/ clean
	make -C ./stage2 clean
	make -C ./stage1-uefi-bootservices-hook clean
