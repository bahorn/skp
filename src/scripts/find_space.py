import sys
from elftools.elf.elffile import ELFFile

# 65kb, can go up to 1MB on most kernels.
# May need adjusting, worked on a 5.15 kernel.
WANT = 0x00_01_00_00


def test(data, start, end):
    for i in range(start, end):
        if data[i] != 0xcc:
            return False

    return True


def main():
    fp = open(sys.argv[1], 'rb')
    data = fp.read()

    fp.seek(0)

    f = ELFFile(fp)

    rodata = f.get_section_by_name('.rodata').header['sh_offset']
    text = f.get_section_by_name('.text').header['sh_offset']

    spot = rodata - text
    start = spot - WANT
    end = spot

    if test(data, start, end):
        print(hex(start))
        return

    start = rodata - WANT
    end = rodata

    if test(data, start, end):
        print(hex(start))
        return

    raise Exception('FAILURE')


if __name__ == "__main__":
    main()
