BITS 64

global runtime_bin:data
global runtime_bin_offset:data 4
global runtime_bin_len:data 4

_begin:

_start_stage2:

%include "uefi.asm"

%include "bios.asm"

%include "initcall.asm"

; We just append this.
_runtime_hook:
    incbin "../kshelf-loader/runtime_hook.bin"

; Now our externals:
runtime_bin:
    dq _start_stage2
runtime_bin_offset:
    dd _initcall_runtime_thunk - _begin
runtime_bin_len:
    dd runtime_bin_offset - _begin
