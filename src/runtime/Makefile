
build:
	make -C kshelf-loader
	make -C ./stage2
	make -C ./stage1-uefi-bootservices-hook
	make -C ./stage0/
	python3 ../scripts/generate_lds.py $(KPATH)/kallsyms $(KPATH)/curr.elf > generated.lds
	ld -T./linker.lds -pie \
		 -Map=output.map \
		./stage0/stage0.o \
		./stage1-uefi-bootservices-hook/stage1.o \
		./stage2/stage2.o \
		./kshelf-loader/kshelf_loader.o \
		$(PAYLOAD) \
		-o all.bin

clean:
	-rm all.bin payload.h output.map generated.lds
	make -C ./stage0/ clean
	make -C ./kshelf-loader/ clean
	make -C ./stage2 clean
	make -C ./stage1-uefi-bootservices-hook clean
