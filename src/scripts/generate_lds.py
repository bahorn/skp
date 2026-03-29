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

PCPU_OFFSET = 8


def find_blocks(data, min_size=WANT):
    blocks = []
    i = len(data) - 1
    while i >= 0:
        if data[i] == 0xcc:
            end = i
            while i >= 0 and data[i] == 0xcc:
                i -= 1
            start = i + 1
            size = end - start + 1
            if size >= min_size:
                blocks.append((start, size))
        else:
            i -= 1
    return blocks


def find_space(path):
    fp = open(path, 'rb')
    data = fp.read()

    fp.seek(0)

    f = ELFFile(fp)

    text = f.get_section_by_name('.text')
    start = text.header['sh_offset']
    end = start + text.header['sh_size']

    # now search from the end of .text for a large enough block of 0xcc

    blocks = find_blocks(data[start:end])
    if len(blocks) == 0:
        raise Exception('FAILURE')

    return start + blocks[0][0]


def kallsyms_line_to_int(line):
    v = line.strip().split(' ')[0]
    return int(f'0x{v}', 16)


def preempt_count(path):
    for line in open(sys.argv[1], 'r'):
        l = line.strip()
        s = l.split(' ')[-1]
        value = l.split(' ')[0]
        if s == '__preempt_count':
            # old kernel, we got the offset
            return kallsyms_line_to_int(line)

        if s == 'pcpu_hot':
            return kallsyms_line_to_int(line) + PCPU_OFFSET

    raise Exception('finding preempt count failed')


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
    print(f'HIDDEN(__preempt_count = {hex(preempt_count(sys.argv[1]))});')

if __name__ == "__main__":
    main()
