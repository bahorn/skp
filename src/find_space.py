import sys
from elftools.elf.elffile import ELFFile


def main():
    f = ELFFile(open(sys.argv[1], 'rb'))
    rodata = f.get_section_by_name('.rodata')
    text = f.get_section_by_name('.text')

    print(hex(rodata.header['sh_offset'] - text.header['sh_offset']))


if __name__ == "__main__":
    main()
