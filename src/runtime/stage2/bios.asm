BITS 64

extern load_offset
extern _initcall_offset
extern startup_64

; this is the code we call just after the kernel is decompressed if we boot via
; BIOS.
; rax contains the address of the entrypoint, which should be startup_64.
global _bios_entry
_bios_entry:
    push rax
    push rcx
    push rdi
    push rsi

; now we need patch the kernel and get stage1 in a suitable place.
 
; so the kernel pads sections with 0xcc, with a 0x20_00_00 alignment, so we
; have a ton of free space to place a payload.
    lea rsi, [rel _initcall_runtime_thunk]
    sub rax, startup_64
    mov rdi, rax
    add rdi, load_offset
    mov rcx, _kshelf_loader_len + (_kshelf_loader - _initcall_runtime_thunk)
    rep movsb


; hook initcall to call our stage1
    mov rdi, load_offset
    sub rdi, _initcall_offset
    add rax, _initcall_offset
    mov dword [rax], edi

; now we can transfer control over
    pop rsi
    pop rdi
    pop rcx
    pop rax
    jmp rax
