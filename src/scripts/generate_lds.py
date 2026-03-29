"""
Generate the linker script we need to include to have all the symbols our
runtime uses.
"""
import sys
import re
from elftools.elf.elffile import ELFFile

SYMBOLS = ['startup_64', 'kallsyms_lookup_name', '__efi_call']
# regex to match the initcall symbol
INITCALL = re.compile('__initcall__kmod_core[_0-9a-z]*regulator_init_complete[_0-9a-z]*')

# 65kb, can go up to 1MB on most kernels.
# May need adjusting, worked on a 5.15 kernel.
WANT = 0x00_01_00_00


def test(data, start, end):
    for i in range(start, end):
        if data[i] != 0xcc:
            return False

    return True


def find_space(path):
    fp = open(path, 'rb')
    data = fp.read()

    fp.seek(0)

    f = ELFFile(fp)

    rodata = f.get_section_by_name('.rodata').header['sh_offset']
    text = f.get_section_by_name('.text').header['sh_offset']

    spot = rodata - text
    start = spot - WANT
    end = spot

    if test(data, start, end):
        return start

    start = rodata - WANT
    end = rodata

    if test(data, start, end):
        return start

    raise Exception('FAILURE')


def kallsyms_line_to_int(line):
    v = line.strip().split(' ')[0]
    return int(f'0x{v}', 16)


def find_symbols(path, symbols):
    text = None
    sym_addr = {symbol: None for symbol in symbols}
    sym_addr['_initcall_offset'] = None

    total = len(sym_addr)
    found = 0

    for line in open(path, 'r'):
        name = line.split(' ')[-1].strip()

        if name == '_text':
            text = kallsyms_line_to_int(line)

        if name in symbols and sym_addr[name] is None:
            sym_addr[name] = kallsyms_line_to_int(line)
            found += 1
        elif INITCALL.fullmatch(name) != None and \
                sym_addr['_initcall_offset'] is None:
            sym_addr['_initcall_offset'] = kallsyms_line_to_int(line)
            found += 1

        if text is not None and found >= total:
            break

    # edge case, where we need to do this before subtracting .text from
    # startup_64
    sym_addr['_initcall_offset'] -= sym_addr['startup_64']

    for symbol in sym_addr.keys():
        if symbol != '_initcall_offset':
            sym_addr[symbol] -= text
    return sym_addr


def main():
    for k, v in find_symbols(sys.argv[1], SYMBOLS).items():
        print(f'HIDDEN({k} = {hex(v)});')
    print(f'HIDDEN(load_offset = {hex(find_space(sys.argv[2]))});')

if __name__ == "__main__":
    main()
