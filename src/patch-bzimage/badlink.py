"""
Implementation of a quick/dirty linking format.

Just prefixing the data with set of structs that can be easily indexed, which
should be easy enough to setup from NASM or whatever.
"""

import struct
from enum import Enum


class RelocTypes(Enum):
    HEADER = 0x0

    # For when we want to write a byte
    BYTE_1 = 0x11
    BYTE_2 = 0x12
    BYTE_4 = 0x14
    BYTE_8 = 0x18

    # For getting an offset that was pre-calculated.
    # I.e an entrypoint
    OFFSET = 0x20


class BadLink:
    MAGIC = b'b4dl1nk\x00'

    def __init__(self, data):
        self._data = bytearray(data)
        self._kv = {}
        self._count = 0
        self._end = 0
        self._extract()

    def get(self):
        """
        Return the data post linking
        """
        for k, v in self._kv.items():
            start = self._end + v['dest']
            end = 0
            match v['type']:
                case RelocTypes.OFFSET:
                    continue
                case RelocTypes.BYTE_1:
                    end = start + 1
                case RelocTypes.BYTE_2:
                    end = start + 2
                case RelocTypes.BYTE_4:
                    end = start + 4
                case RelocTypes.BYTE_8:
                    end = start + 8
                case _ as e:
                    raise Exception(f'Unimplemented {e}')

            # Not set, leave as is. Used to pass info back.
            if v['value'] is None:
                continue

            if len(v['value']) != (end - start):
                raise Exception('Size doesnt match!')

            self._data[start:end] = v['value']

        return self._data[self._end:]

    def set_key(self, key, value):
        """
        Just set the value to be used later.
        """
        if self._kv.get(key) is None:
            raise Exception('Invalid key!')
        self._kv[key]['value'] = value

    def get_key(self, key):
        """
        Retrieve a value for a key.
        """
        kv = self._kv[key]
        d = kv['dest']
        if kv['type'] is not RelocTypes.OFFSET:
            d += self._end
        match kv['type']:
            case RelocTypes.OFFSET:
                return d
            case RelocTypes.BYTE_1:
                return self._data[d:d+1]
            case RelocTypes.BYTE_2:
                return self._data[d:d+2]
            case RelocTypes.BYTE_4:
                return self._data[d:d+4]
            case RelocTypes.BYTE_8:
                return self._data[d:d+8]
            case _ as e:
                raise Exception(f'Unimplemented type {e}')

    def get_key_offset(self, key):
        kv = self._kv[key]
        return kv['dest']

    def size(self):
        return len(self._data[self._end:])

    def _extract(self):
        """
        Process the badlink data and setup our structs.
        """
        header = self._data[0:16]
        if header[0:8] != self.MAGIC:
            raise Exception('Not a badlink file!')
        self._count = struct.unpack('<I', header[8:12])[0]
        self._end = struct.unpack('<I', header[12:16])[0]

        for i in range(1, self._count + 1):
            reloc = self._data[16 * i:16 * (i + 1)]
            rname = bytes(reloc[0:7])
            rtype = RelocTypes(int(reloc[7]))
            rdest = struct.unpack('<Q', reloc[8:16])[0]
            self._kv[rname] = {
                'name': rname,
                'type': rtype,
                'dest': rdest,
                'value': None
            }
