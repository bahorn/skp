; Our goal here is to hook exit_boot_services, then continue boot as normal.
section .uefi_hook

extern _stage1_main
extern _original_uefi_offset

global _uefi_entry
_uefi_entry:
    push rax
    push rcx
    push rdx
    push r8
    push r9
    call _stage1_main
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax

; lets call the original entrypoint
; its easier to ensure we get the relative instruction I want if I just write
; out the opcode by hand.
    db 0xe8
    dd _original_uefi_offset
global _insn_original_uefi_offset
_insn_original_uefi_offset:

    align 32, db 0xff
