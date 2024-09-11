BITS 64


%include "thunk-uefi.asm"

%include "thunk-bios.asm"

%include "thunk-initcall.asm"

; We just append this.
_runtime_hook:
