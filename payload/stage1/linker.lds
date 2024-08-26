ENTRY(entry)
OUTPUT_FORMAT("binary")

INCLUDE "generated/offsets.lds"

# Needed to compute offsets to symbols.
INCLUDE "generated/load.lds"
LOAD_ADDRESS = startup_64 + LOAD_OFFSET;

SECTIONS
{
    . = LOAD_ADDRESS;
    .text.start : {
        *(.text.start)
    }

    # want some spacing
    . = . + 128;
    . = ALIGN(16);
    .text : {
        *(.text)
    }

    .got : {
        *(.got)
    }

    .rodata : ALIGN(16) {
        *(.rodata)
    }

    .data : ALIGN(16) {
        _DATA_START_ = .;
        *(.data)
        _DATA_END_ = .;
    }

    .bss : ALIGN(16) {
        _BSS_START_ = .;
        *(.bss)
        _BSS_END_ = .;
    }

    /DISCARD/ : { *(.note*) }
}
