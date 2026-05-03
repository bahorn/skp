"""
This handles linking the payload against the target kernel.

Builds the runtime with the payload (if defined), then allows reading values
from the map file to get offsets.
"""
import os
import subprocess
from generate_lds import generate_lds, wrap_lds
from consts import WANT


def link(runtime, symbols, linker_script, payload):
    with open('/tmp/generated.lds', 'w') as f:
        f.write(wrap_lds(symbols))

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
    return data


class BadLink:
    def __init__(self, runtime, kallsyms, linker_script, unpacked_kernel,
                 payload=None):
        self._runtime = runtime
        self._kallsyms = kallsyms
        self._linker_script = linker_script
        self._unpacked_kernel = unpacked_kernel
        self._payload = payload
        temp_symbols = generate_lds(kallsyms, unpacked_kernel, want=None)
        self._size = len(
            link(runtime, temp_symbols, linker_script, payload)
        )

        # We are using the map file we get from the test link, not the final
        # artifact.
        # Shouldn't be an issue, just noting it!
        self._mapfile = self._extract('/tmp/output.map')
        self._to_set = {}

        os.remove('/tmp/output.map')

    def get_key(self, key):
        return self._mapfile[key]

    def set_key(self, key, value):
        self._to_set[key] = value

    def get(self):
        """
        Return the data post linking
        """
        symbols = generate_lds(
            self._kallsyms, self._unpacked_kernel,
            want=min(WANT, self._size)
        )
        for k, v in self._to_set.items():
            symbols[k] = v
        print(wrap_lds(symbols))
        data = link(
            self._runtime, symbols, self._linker_script, payload=self._payload,
        )
        return bytearray(data)

    def size(self):
        return self._size

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
