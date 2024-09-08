"""
Replace the bios_e entry with the real one.
"""
import sys
import struct


def bios_hook(data):
    pattern = b'DCBAhack the planet\x00dcba'

    start = struct.unpack('<I', data[0xc:0x10])[0]

    offset = (data.find(pattern) + len(pattern)) - start

    data[0x28:0x30] = struct.pack('<Q', offset)

    return data


def main():
    data = bytearray(open(sys.argv[1], 'rb').read())
    data = bios_hook(data)
    open(sys.argv[1], 'wb').write(data)


if __name__ == "__main__":
    main()
