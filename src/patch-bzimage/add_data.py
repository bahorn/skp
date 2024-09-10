"""
Function to append data to a kernel bzImage, and add apply our hooks.
"""
import struct
import pefile
from badlink import BadLink
from consts import PAGE_SIZE
from utils import pad_size, pad
from bios import bios_patch


def add_data(pe_data_orig, data, apply_bios_patch=True, apply_uefi_patch=True):
    """
    Add a new section to store our patch in the PE, then append our data, and
    install the patches to transfer control to our payload.
    """
    bl = BadLink(data)
    # We can fetch the real entrypoints like this:
    bios_start = bl.get_key(b'bios_e\x00')
    _code32 = bl.get_key(b'code32\x00')

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
    pe_data += b'\x00' * (PAGE_SIZE * 1)
    to_pad_with = curr_virtual_size - curr_real_size

    # Calculate things before appending our data
    offset = len(pe_data)
    uefi_offset = to_pad_with + offset

    # Replacing the UEFI entrypoint
    pe = pefile.PE(data=pe_data)
    if apply_uefi_patch:
        new_entrypoint = uefi_offset + bl.get_key(b'uefi_e\x00')
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_entrypoint
    pe_data = bytearray(pe.write())

    called_from = uefi_offset + bl.get_key_offset(b'uefi_o\x00') + 4
    orig_entrypoint = old_entrypoint - called_from

    # need to calculate an offset to use to call the old entrypoint
    bl.set_key(b'uefi_o\x00', struct.pack('<i', orig_entrypoint))

    k = 0x100_000 + offset + bl.get_key(b'o_ptch\x00') - text_start
    bl.set_key(b'o_tocp\x00', struct.pack('<I', k))

    # need to set the offsets we use patch the bios.
    b_start, b_dest = bios_patch(pe_data, offset, text_start, bios_start)
    bl.set_key(b'o_bios\x00', struct.pack('<I', b_dest))
    bl.set_key(b'o_dest\x00', struct.pack('<I', b_start))

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

    # We do not need to do any more for UEFI as we already hooked it's
    # entrypoint, but need to now deal with BIOS.

    # Our BIOS Patch to transfer control, we use a code32_start hook to modify
    # an instruction.

    if apply_bios_patch:
        new_code32 = 0x100_000 + offset + _code32 - text_start
        pe_data[0x214:0x214 + 4] = struct.pack('<I', new_code32)

    return pe_data
