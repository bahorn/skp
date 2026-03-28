BITS 64

%define _kshelf_loader_len _kshelf_loader_end - _kshelf_loader

_begin:

_start_stage2:

%include "uefi.asm"

%include "bios.asm"

%include "initcall.asm"

; We just append this.
_kshelf_loader:
    incbin "../kshelf-loader/kshelf_loader.bin"
_kshelf_loader_end:

global runtime_bin:data 8
runtime_bin:
    dq _start_stage2 - runtime_bin

global runtime_bin_offset:data 4
runtime_bin_offset:
    dd _initcall_runtime_thunk - _begin

global runtime_bin_len:data 4
runtime_bin_len:
    dd runtime_bin_offset - _begin
