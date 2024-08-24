import sys
import re


def main():
    f = open(sys.argv[1])
    for line in f:
        address, symbol_type, symbol = re.sub('\[[a-z_A-Z0-9]*\]', '', line.strip()).split(' ')
        print(f'{symbol} = 0x{address};')


if __name__ == "__main__":
    main()
