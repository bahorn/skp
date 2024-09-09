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
