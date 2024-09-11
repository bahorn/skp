; This is used by the BIOS and UEFI ExitBootServices Direct patch
    db "initcall_runtime_thunk", 0

; This is the code that will be copied into a cavity into the kernel image.
; So if get here we got patched into the kernel and called via an initcall.
_initcall_runtime_thunk:
; Want to pass in our known address of _text
; In this case, it's RIP relative back.
    lea rdi, [rel $-_stage1_offset-_startup_64_offset]
    mov rsi, 1
    jmp _runtime_hook
