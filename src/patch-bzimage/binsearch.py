import re
import sys

from keystone import \
        Ks, KS_ARCH_X86, KS_MODE_64, KS_OPT_SYNTAX_ATT
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


class SearchObject:
    def pattern(self):
        return self._data

    def size(self):
        return len(self._data)


class FixedBytes(SearchObject):
    def __init__(self, data):
        res = bytes(
            ''.join(map(lambda x: '\\x{0:0{1}X}'.format(x, 2), data)),
            'ascii'
        )

        self._data = res


class SkipBytes(SearchObject):
    def __init__(self, n_bytes=1):
        self._data = b'.' * n_bytes


class Assembly(SearchObject):
    def __init__(self,
                 code,
                 syntax=KS_OPT_SYNTAX_ATT,
                 arch=KS_ARCH_X86,
                 mode=KS_MODE_64):
        # Initialize engine in X86-32bit mode
        ks = Ks(arch, mode)
        ks.syntax = syntax
        encoding, count = ks.asm(code)

        res = bytes(
                ''.join(map(lambda x: '\\x{0:0{1}X}'.format(x, 2), encoding)),
                'ascii'
            )
        self._data = res


class BinSearch:
    def __init__(self, patterns):
        pattern = BinSearch.generate_pattern(patterns)
        self._pattern = re.compile(
            pattern,
            flags=re.S + re.M
        )

    def search(self, data):
        res = []
        for match in self._pattern.finditer(data):
            res.append((match.start(), match.end(), match.group()))
        return res

    @staticmethod
    def generate_pattern(so):
        return b''.join(map(lambda x: x.pattern(), so))


def disassemble(data):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(data, 0x00000000):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))


def main():
    code1 = """xorl %eax, %eax"""
    code2 = """
    subq %rdi, %rcx
    shrq $3, %rcx
    rep stosq
    pushq %rsi
    """
    bs = BinSearch([
        Assembly(code1),
        SkipBytes(14),
        Assembly(code2)
    ])

    data = open(sys.argv[1], 'rb').read()

    for start, end, match in bs.search(data):
        disassemble(data[start:end+64])


if __name__ == "__main__":
    main()
