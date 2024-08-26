
build:
	../tools/xxd.py $(PAYLOAD) payload > ./payload.h
	SYMBOLS=$(SYMBOLS) LOAD_OFFSET=$(LOAD_OFFSET) \
			make -C ./stage1/
	SYMBOLS=$(SYMBOLS) LOAD_OFFSET=$(LOAD_OFFSET) \
			make -C ./stage0/
	cat ./stage0/stage0.bin ./stage1/stage1.bin > ./all.bin


clean:
	-rm all.bin payload.h
	make -C ./stage1/ clean
	make -C ./stage0/ clean
