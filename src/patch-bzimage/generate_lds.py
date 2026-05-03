"""
Generate a partial linker script defining symbols we need to include to link
the runtime.
"""
import sys
import re
from elftools.elf.elffile import ELFFile
from consts import SYMBOLS, INITCALL, WANT, PCPU_OFFSET


def find_blocks(data, min_size):
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


def find_space(path, want):
    fp = open(path, 'rb')
    data = fp.read()

    fp.seek(0)

    f = ELFFile(fp)

    text = f.get_section_by_name('.text')
    start = text.header['sh_offset']
    end = start + text.header['sh_size']

    # now search from the end of .text for a large enough block of 0xcc

    blocks = find_blocks(data[start:end], min_size=WANT)
    if len(blocks) == 0:
        raise Exception('FAILURE')

    return start + blocks[0][0]


def kallsyms_line_to_int(line):
    v = line.strip().split(' ')[0]
    return int(f'0x{v}', 16)


def preempt_count(path):
    for line in open(path, 'r'):
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

    initcall = re.compile(INITCALL)

    total = len(sym_addr)
    found = 0

    for line in open(path, 'r'):
        name = line.split(' ')[-1].strip()

        if name == '_text':
            text = kallsyms_line_to_int(line)

        if name in symbols and sym_addr[name] is None:
            sym_addr[name] = kallsyms_line_to_int(line)
            found += 1
        elif initcall.fullmatch(name) != None and \
                sym_addr['_initcall_offset'] is None:
            sym_addr['_initcall_offset'] = kallsyms_line_to_int(line)
            found += 1

        if text is not None and found >= total:
            break

    for symbol in sym_addr.keys():
        sym_addr[symbol] -= text
    return sym_addr


def generate_lds(kallsyms_path, unpacked_kernel_path, want=WANT):
    res = {}
    for k, v in find_symbols(kallsyms_path, SYMBOLS).items():
        res[k] = v

    # We use load_offset to set the address of the patch from the rest of the
    # kernel, which we store in spare space in the kernel.
    # So if we want to set a good value for this, we actually need to link the
    # payload once to see its size, then link again once we know the size.
    if want is None:
        res['load_offset'] = 0
        # symbols we set in add_data.py
        res['_original_uefi_offset'] = 0
        res['_offset_to_copy'] = 0
        res['_offset_dest'] = 0
        res['_offset_bios_entry'] = 0
    else:
        res['load_offset'] = find_space(unpacked_kernel_path, want)

    res['__preempt_count'] = preempt_count(kallsyms_path)
    return res


def wrap_lds(lds):
    res = []
    for name, value in lds.items():
        res.append(f'HIDDEN({name} = {hex(value)});')
    return '\n'.join(res)


if __name__ == "__main__":
    main()
