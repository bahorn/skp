BITS 64
; This is the thunk that will get called by our Runtime Hook
; Remember, we are using the ms abi here.

; The original GetVariable()
_original:
    dq 0

_to_restore:
    dq 0

_entry:
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

; We just append this.
_runtime_hook:
