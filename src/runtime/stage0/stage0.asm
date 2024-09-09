BITS 64


; This is a custom linking format just to make it easier to patch values in this
; directly.
_bad_link_header:
    db "b4dl1nk", 0
    dd (_bad_link_reloc_end - _bad_link_reloc_start) / 16
    dd _badlink_end

_bad_link_reloc_start:

; uefi entrypoint
    db "uefi_e", 0
    db 0x20 ; offset type, for reading
    dq _uefi_entry - _badlink_end

; bios entrypoint
; adjusted later on.
    db "bios_e", 0
    db 0x20 ; offset type for reading.
    dq 0

; original uefi entrypoint
    db "uefi_o", 0
    db 0x14
    dq _original_uefi_offset - _badlink_end

; Offset to our _code32 hook
    db "code32", 0
    db 0x20
    dq _code32_hook - _badlink_end

    db "o_dest", 0
    db 0x14
    dq _offset_dest - _badlink_end

    db "o_bios", 0
    db 0x14
    dq _offset_bios_entry - _badlink_end

    db "o_tocp", 0
    db 0x14
    dq _offset_to_copy - _badlink_end

    db "o_ptch", 0
    db 0x20
    dq _to_copy - _badlink_end

_bad_link_reloc_end:

    align 64, db 0x00

_badlink_end:


%include "./uefi.asm"
%include "./code32.asm"

_our_hook:
