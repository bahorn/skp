"""
Get the offset for a symbol from _text
"""
import sys


def kallsyms_line_to_int(line):
    v = line.strip().split(' ')[0]
    return int(f'0x{v}', 16)


def main():
    text = None
    sym_addr = None

    # need to find the initcall for regulator_init_complete, our chosen hook
    # destination.
    for line in open(sys.argv[1], 'r'):
        name = line.split(' ')[-1].strip()

        if name == '_text':
            text = kallsyms_line_to_int(line)

        if name == sys.argv[2]:
            sym_addr = kallsyms_line_to_int(line)

        if text is not None and sym_addr is not None:
            break

    print(hex(sym_addr - text))


if __name__ == "__main__":
    main()
