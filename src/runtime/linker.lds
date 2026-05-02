OUTPUT_FORMAT("binary")

INCLUDE "/tmp/generated.lds"

SECTIONS
{
    .uefi_hook : {
        *(.uefi_hook)
    }

    .code32_hook : {
        *(.code32_hook)
    }

    # Stage1, which is the UEFI stage (bypassed for BIOS booting)

    .stage1.text.start : ALIGN(16) {
        *(.stage1.text.start)
    }

    # want some spacing
    .stage1.text : ALIGN(16) {
        *(.stage1.text)
        *(.stage1.rodata)
        *(.stage1.data)
        *(.stage1.bss)
        *(.stage1.data.rel.local)
    }

    # Stage 2, which is what is ran when we are in the kernel, used to load the
    # real payload.

    .stage2 : ALIGN(16) {
        *(.stage2.*)
    }

    # The loader for our paylaod
    .kshelf_loader.start : {
        *(.kshelf_loader.text.start)
    }

    .kshelf_loader.text : ALIGN(16) {
        *(.kshelf_loader.text)
        *(.kshelf_loader.rodata)
        *(.kshelf_loader.data)
        *(.kshelf_loader.bss)
        *(.kshelf_loader.data.rel.local)
    }

    # now the payload, stored in the .data section but including these for the
    # sake of it.

    .payload : ALIGN(16) {
        *(.text)
        *(.data)
        *(.bss)
    }

    # the end!

    _kshelf_loader_end = .;

    /DISCARD/ : {
        *(*.note*)
        *(.note*)
        *(*.comment*)
        *(.debug*)
        *(.stage1*)
    }
}
