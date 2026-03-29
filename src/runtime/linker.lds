OUTPUT_FORMAT("binary")

INCLUDE "generated.lds"

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
        *(.stage1.data)
    }

    .stage1.bss : ALIGN(16) {
        *(.stage1.bss)
    }

    . = . + 64;
    . = ALIGN(16);

    .stage2 : ALIGN(16) {
        *(.stage2.*)
    }

    /DISCARD/ : {
        *(*.note*)
        *(.note*)
        *(*.comment*)
    }
}
