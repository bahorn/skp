"""
We need the gs offset of __preempt_count to disable preemption in the UEFI
runtime hook.
"""
import sys

PCPU_OFFSET = 8


def main():
    for line in open(sys.argv[1], 'r'):
        l = line.strip()
        s = l.split(' ')[-1]
        value = l.split(' ')[0]
        if s == '__preempt_count':
            # old kernel, we got the offset
            print(hex(int(f'0x{value}', 16)))
            return

        if s == 'pcpu_hot':
            print(hex(int(f'0x{value}', 16) + PCPU_OFFSET))
            return


if __name__ == "__main__":
    main()
