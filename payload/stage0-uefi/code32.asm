    BITS 32
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
_offset_to_copy:
    db 0, 0, 0, 0

; add. need to pass this in here
    db 0xbf
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

_to_copy:
; code to call _bios_entry, our code to patch the kernel in the BIOS boot path.
    db 0x68
_offset_bios_entry:
    db 0, 0, 0, 0
    ret
_to_copy_end:
