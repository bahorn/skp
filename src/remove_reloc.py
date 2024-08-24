"""
.reloc section exists in older bzImages.

It's not need according so recent commits:
https://github.com/torvalds/linux/commit/fa5750521e0a4efbc1af05223da9c4bbd6c21c83

So we can remove it and free up space, which lets us define a new section.
"""
import sys
import pefile


def has_reloc(data):
    pe = pefile.PE(data=data)
    # check if there is a reloc section, if not, just return
    idx = 0

    for sidx, section in enumerate(pe.sections):
        if section.Name == b'.reloc\x00\x00':
            idx = sidx
            return idx

    return None


def remove_reloc(data):
    idx = has_reloc(data)

    if idx is None:
        return data

    pe = pefile.PE(data=data)

    modified_data = bytearray(data)
    # We are removing a section
    for sidx in range(len(pe.sections)):
        # skip as we don't care
        if sidx < idx:
            continue

        curr = pe.sections[sidx].__file_offset__

        next_data = b'\x00'*0x28
        if sidx < len(pe.sections) - 1:
            next = pe.sections[sidx + 1].__file_offset__
            next_data = modified_data[next:next+0x28]

        modified_data[curr:curr+0x28] = next_data

    pe = pefile.PE(data=modified_data)
    pe.FILE_HEADER.NumberOfSections -= 1
    pe_data = bytearray(pe.write())
    return pe_data


def test():
    res = remove_reloc(open(sys.argv[1], 'rb').read())
    open(sys.argv[2], 'wb').write(res)


if __name__ == "__main__":
    test()
