OUTPUT_FORMAT("binary")

SECTIONS
{
    .header : {
        *(.header)
    }

    .uefi_hook : {
        *(.uefi_hook)
    }

    .code32_hook : {
        *(.code32_hook)
    }

    . = . + 64;
    . = ALIGN(16);

    .stage1.text.start : ALIGN(16) {
        *(.stage1.text.start)
    }

    # want some spacing
    .stage1.text : ALIGN(16) {
        *(.stage1.text)
    }

    .stage1.rodata : ALIGN(16) {
        *(.stage1.rodata)
    }

    .stage1.data : ALIGN(16) {
        _DATA_START_ = .;
        *(.stage1.data)
        _DATA_END_ = .;
    }

    .stage1.bss : ALIGN(16) {
        _BSS_START_ = .;
        *(.stage1.bss)
        _BSS_END_ = .;
    }

    . = . + 64;
    . = ALIGN(16);

    .stage2 : ALIGN(16) {
        *(.stage2.*)
    }

    /DISCARD/ : { *(.note*) }
}
