import sys
from elftools.elf.elffile import ELFFile

# just under 1mb
# May need adjusting, worked on a 5.15 kernel.
WANT = 0x00_01_00_00


def main():
    fp = open(sys.argv[1], 'rb')
    data = fp.read()

    fp.seek(0)

    f = ELFFile(fp)

    rodata = f.get_section_by_name('.rodata')
    text = f.get_section_by_name('.text')

    spot = rodata.header['sh_offset'] - text.header['sh_offset']

    start = spot - WANT
    end = spot

    for i in range(start, end):
        assert(data[i] == 0xcc)

    print(hex(spot - WANT))


if __name__ == "__main__":
    main()
