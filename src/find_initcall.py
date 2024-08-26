"""
Get the offset of the initcall we want to take over.
"""
import sys


def kallsyms_line_to_int(line):
    v = line.strip().split(' ')[0]
    return int(f'0x{v}', 16)


def main():
    initcall_ric = None
    entrypoint = None

    # need to find the initcall for regulator_init_complete, our chosen hook
    # destination.
    for line in open(sys.argv[1], 'r'):
        if ' startup_64\n' in line:
            entrypoint = kallsyms_line_to_int(line)
            continue

        if "__initcall__kmod" not in line:
            continue

        if "regulator_init_complete" not in line:
            continue

        initcall_ric = kallsyms_line_to_int(line)
        if entrypoint is not None:
            break

    print(hex(initcall_ric - entrypoint))


if __name__ == "__main__":
    main()
