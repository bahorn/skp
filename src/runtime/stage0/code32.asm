    BITS 32

section .code32_hook

extern _offset_to_copy
extern _offset_dest
extern _offset_bios_entry

global _code32_hook
_code32_hook:
    cld
    cli

; we are required to preseve these
    push edi
    push esi

    mov esi, _offset_to_copy

; add. need to pass this in here
    mov edi, _offset_dest

    mov ecx, _to_copy_end - _to_copy
    rep movsb

; restore registers
    pop esi
    pop edi

; Transfer control back to the original entrypoint
    push 0x100_000
    ret

global _to_copy
_to_copy:
; code to call _bios_entry, our code to patch the kernel in the BIOS boot path.
    push _offset_bios_entry
    ret
_to_copy_end:
