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
; we need to pass to 
    pop rax
    push rax
    sub rax, __efi_call + 40

; Now do the usual register preservation
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11

; call our hook to setup our payload.
    push rax
    push rdi
    mov rdi, rax
    call _runtime_hook

; get the registers back to normal
    pop rdi
    pop rax
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx

; restore and call the original entry now that we've done own work.
    mov rax, [rel _original]
    push rbx
    mov rbx, [rel _to_restore]
    mov [rbx], rax
    pop rbx
    push rax
    ret

; We just append this.
_runtime_hook:
