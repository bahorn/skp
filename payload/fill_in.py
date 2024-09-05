"""
Replace the bios_e entry with the real one.
"""
import sys
import struct

pattern = b'DCBAhack the planet\x00dcba'

data = bytearray(open(sys.argv[1], 'rb').read())

start = struct.unpack('<I', data[0xc:0x10])[0]

offset = (data.find(pattern) + len(pattern)) - start

data[0x28:0x30] = struct.pack('<Q', offset)

open(sys.argv[1], 'wb').write(data)
