PAGE_SIZE = 4096
BIOS_TARGET_ADDRESS = 0x100_000

# For the linking against the kernel.

SYMBOLS = ['startup_64', 'kallsyms_lookup_name', '__efi_call']
# regex to match the initcall symbol
INITCALL = '__initcall__kmod_core[_0-9a-z]*regulator_init_complete[_0-9a-z]*'

# 65kb, can go up to 1MB on most kernels.
# May need adjusting, worked on a 5.15 kernel.
WANT = 0x00_01_00_00

PCPU_OFFSET = 8
