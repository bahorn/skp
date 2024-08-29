
build:
	../tools/xxd.py $(PAYLOAD) payload > ./payload.h
	SYMBOLS=$(SYMBOLS) LOAD_OFFSET=$(LOAD_OFFSET) \
			make -C ./stage1/
	../tools/xxd.py ./stage1/stage1.bin stage1 > ./stage1.h
	SYMBOLS=$(SYMBOLS) LOAD_OFFSET=$(LOAD_OFFSET) make -C ./hook_bootservices/
	SYMBOLS=$(SYMBOLS) LOAD_OFFSET=$(LOAD_OFFSET) \
			make -C ./stage0/
	cat ./stage0/stage0.bin ./hook_bootservices/bootservices_hook.bin > ./all.bin


clean:
	-rm all.bin payload.h
	make -C ./stage1/ clean
	make -C ./stage0/ clean
	make -C ./hook_bootservices/ clean
