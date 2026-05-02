    BITS 32

section .code32_hook


global _code32_hook
_code32_hook:
    cld
    cli

; we are required to preseve these
    push edi
    push esi

; our goal is to just copy a few instructions to a target position
; so this is done like this because of what i asssume is a nasm bug.
; the offset being generated in the instruction was wrong
; doing this because lea requires setting up all the segments and thats a pain.
    db 0xbe
global _offset_to_copy
_offset_to_copy:
    db 0, 0, 0, 0

; add. need to pass this in here
    db 0xbf
global _offset_dest
_offset_dest:
    db 0, 0, 0, 0

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
    db 0x68
global _offset_bios_entry
_offset_bios_entry:
    db 0, 0, 0, 0
    ret
_to_copy_end:
