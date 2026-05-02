"""
This handles linking the payload against the target kernel.

Builds the runtime with the payload (if defined), then allows reading values
from the map file to get offsets.
"""
import os
import subprocess
from generate_lds import generate_lds


class BadLink:
    def __init__(self, runtime, kallsyms, linker_script, unpacked_kernel,
                 payload=None):
        self._data = self._build_runtime(
            runtime, kallsyms, linker_script, unpacked_kernel, payload
        )
        self._mapfile = self._extract('/tmp/output.map')
        self._to_set = {}

        os.remove('/tmp/output.map')

    def _build_runtime(self, runtime, kallsyms, linker_script, unpacked_kernel,
                      payload=None):
        """
        Link the runtime.
        """
        # Writing the symbols to generated.lds so the linker script can have it
        # defined.
        symbols = '\n'.join(generate_lds(kallsyms, unpacked_kernel))
        print(symbols)
        with open('/tmp/generated.lds', 'w') as f:
            f.write(symbols)
        # now link the kernel with the generated scripts
        cmd = [
            'ld', f'-T{linker_script}', '-pie',
            '-Map=/tmp/output.map',
            '-o', '/tmp/runtime.bin',
            runtime
        ]
        if payload is not None:
            cmd.append(payload)
        data = subprocess.run(cmd)

        data = b''
        with open('/tmp/runtime.bin', 'rb') as f:
            data = f.read()

        os.remove('/tmp/generated.lds')
        os.remove('/tmp/runtime.bin')
        return bytearray(data)

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
