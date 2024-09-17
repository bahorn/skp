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
    inc dword gs:__preempt_count
    call _runtime_hook
    dec dword gs:__preempt_count

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
