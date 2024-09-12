"""
Function to identify where to patch to take control post kernel decompression.
"""
from binsearch import FixedBytes, SkipBytes, BinSearch


def bios_patch(pe_data, offset, text_offset=0x5000, bios_start=0):
    # Patching for BIOS
    # targetting the end of startup_64, in Lrelocated.
    # arch/x86/boot/compressed/head_64.S
    # have to match on two sequences, on for newer kernels and one for older as
    # there has been some changes in what is otherwise a pretty stable part of
    # the kernel tree.
    # for the post 6.6 we overwrite some instructions that get used for error
    # handling, which on correctly booted systems isn't an issue.
    # pre 6.6, should be clean, just overwriting a large nop instruction used
    # for padding and the jmp to rax.

    patterns = [
        # post 6.6
        {
            'offset': 3,
            'pattern': [
                FixedBytes(b'\x4c\x89\xfe'),
                FixedBytes(b'\xff\xe0'),
                FixedBytes(b'\xf4\xeb\xfd\x66\x0f\x1f\x44\x00\x00')
            ]
        },
        # pre 6.6
        {
            'offset': 6,
            'pattern': [
                FixedBytes(b'\xe8'),
                SkipBytes(4),
                FixedBytes(b'\x5e'),
                FixedBytes(b'\xff\xe0'),
            ]
        }
    ]

    match_offset = 0
    matches = []

    for pattern in patterns:
        bs = BinSearch(pattern['pattern'])
        match_offset = pattern['offset']
        matches = bs.search(pe_data)

        if len(matches) == 1:
            break

    if len(matches) != 1:
        raise Exception('pattern matching bios sequence failed!')

    # Our takeover code.
    # 0x5000 is the start of .text
    target_addr = 0x100_000 + offset + bios_start - text_offset

    # we'll be jumping back down to an old mapping at a fixed address.
    start = 0x100_000 + matches[0][0] + match_offset - text_offset

    return (start, target_addr)
