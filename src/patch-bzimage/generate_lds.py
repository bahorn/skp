"""
Generate a partial linker script defining symbols we need to include to link
the runtime.
"""
import re
from elftools.elf.elffile import ELFFile
from consts import SYMBOLS, INITCALL, WANT, PCPU_OFFSET


def find_blocks(data, min_size):
    """
    Searches data for a block containing enough continous 0xcc bytes.
    """
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


class Kernel:
    """
    Wrapper around the kernel image to allow getting the information we need for
    the linker script.
    """

    def __init__(self, kpath):
        f = open(kpath, 'rb')
        self._data = f.read()
        f.seek(0)
        self._elf = ELFFile(f)

        symtab = self._elf.get_section_by_name('.symtab')
        self._syms = {}
        # annoyingly slow, only have to do this so we can regex match on the
        # initcall we want to hook.
        for symbol in symtab.iter_symbols():
            if symbol.name not in self._syms:
                self._syms[symbol.name] = []
            self._syms[symbol.name].append(symbol.entry.st_value)

    def data(self):
        return self._data

    def elf(self):
        return self._elf

    def syms(self):
        return self._syms.keys()

    def get(self, symbol):
        return self._syms.get(symbol)

    def find_space(self, want):
        text = self._elf.get_section_by_name('.text')
        start = text.header['sh_offset']
        end = start + text.header['sh_size']

        # now search from the end of .text for a large enough block of 0xcc
        blocks = find_blocks(self._data[start:end], min_size=WANT)
        if len(blocks) == 0:
            raise Exception('FAILURE')

        return start + blocks[0][0]

    def preempt_count(self):
        res = self.get('__preempt_count')
        if res is not None:
            return res[0]

        res = self.get('pcpu_hot')
        if res is not None:
            res = res[0]
            res += PCPU_OFFSET
            return res

        raise Exception('finding preempt count failed')

    def find_symbols(self, symbols):
        text = None
        sym_addr = {symbol: None for symbol in symbols}
        sym_addr['_initcall_offset'] = None

        initcall = re.compile(INITCALL)

        text = self.get('_text')[0]
        for symbol in symbols:
            sym_addr[symbol] = self.get(symbol)
            assert(len(sym_addr[symbol]) == 1)

        for sym in self.syms():
            if initcall.fullmatch(sym) is not None and \
                    sym_addr['_initcall_offset'] is None:
                sym_addr['_initcall_offset'] = self.get(sym)
                assert(len(sym_addr['_initcall_offset']) == 1)

        for symbol in sym_addr.keys():
            sym_addr[symbol] = sym_addr[symbol][0]
            sym_addr[symbol] -= text

        return sym_addr


def generate_lds(kernel, want=WANT, direct_patching=False):
    res = {}
    for k, v in kernel.find_symbols(SYMBOLS).items():
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
        res['load_offset'] = kernel.find_space(want)

    res['_skip_direct_patching'] = int(direct_patching)
    res['__preempt_count'] = kernel.preempt_count()
    return res


def wrap_lds(lds):
    res = []
    for name, value in lds.items():
        res.append(f'HIDDEN({name} = {hex(value)});')
    return '\n'.join(res)
