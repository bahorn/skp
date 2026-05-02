"""
Tool for reading / writing files based on an mapfile produced by a linker.

Used to adapt the payload to match the kernel in add_data.py.
"""


class BadLink:
    def __init__(self, data, mapfile):
        self._data = bytearray(data)
        self._mapfile = self._extract(mapfile)
        self._to_set = {}

    def get_key(self, key):
        return self._mapfile[key]

    def set_key(self, key, value, size=4):
        if key not in self._mapfile:
            raise Exception('undefined symbol being set!')
        offset = self._mapfile[key]
        self._to_set[key] = (offset, value, size)

    def get(self):
        """
        Return the data post linking
        """
        for key, (offset, value, size) in self._to_set.items():
            self._data[offset:offset + size] = value

        return self._data

    def size(self):
        return len(self._data)


    def _extract(self, mapfile):
        found = False
        res = {}
        with open(mapfile) as f:
            lines = f.read().split('\n')
            for line in lines:
                l = line.strip()
                if l == 'Linker script and memory map':
                    found = True
                    continue
                elif l == '/DISCARD/':
                    found = False
                    continue

                if not found:
                    continue
                if l == '':
                    continue

                l = l.split()
                if len(l) != 2:
                    continue

                # filtering the sizes of sections.
                try:
                    int(l[1], 16)
                    continue
                except:
                    pass

                res[l[1]] = int(l[0], 16)

        # first symbol
        offset = res['_uefi_entry']
        for key in res.keys():
            res[key] -= offset
        return res
