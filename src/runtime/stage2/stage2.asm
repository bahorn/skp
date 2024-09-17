BITS 64


%include "uefi.asm"

%include "bios.asm"

%include "initcall.asm"

; We just append this.
_runtime_hook:
    incbin "../kshelf-loader/runtime_hook.bin"
