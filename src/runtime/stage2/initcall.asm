; This is the code that will be copied into a cavity into the kernel image.
; So if get here we got patched into the kernel and called via an initcall.
_initcall_runtime_thunk:
; Want to pass in our known address of _text
; In this case, it's RIP relative back.
    lea rdi, [rel $-_stage1_offset-_startup_64_offset]
    mov rsi, 1
    mov rdx, _kallsyms_offset
    jmp _kshelf_loader
