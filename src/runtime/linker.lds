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

    .hook : {
        *(.hook)
    }

    /DISCARD/ : { *(.note*) }
}
