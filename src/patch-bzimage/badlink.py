"""
This handles linking the payload against the target kernel.

Builds the runtime with the payload (if defined), then allows reading values
from the map file to get offsets.
"""
import os
import subprocess
from generate_lds import generate_lds, wrap_lds, Kernel
from consts import WANT


def link(runtime, symbols, linker_script, payload):
    pid = os.getpid()
    runtime_fd = os.memfd_create('runtime')

    ls = linker_script + wrap_lds(symbols)
    linker_script_fd = os.memfd_create('linker_script')
    os.write(linker_script_fd, bytes(ls, 'ascii'))

    mapfile_fd = os.memfd_create('mapfile')

    # now link the kernel with the generated scripts
    cmd = [
        'ld', f'-T/proc/{pid}/fd/{linker_script_fd}', '-pie',
        f'-Map=/proc/{pid}/fd/{mapfile_fd}',
        '-o', f'/proc/{pid}/fd/{runtime_fd}',
        runtime
    ]
    if payload is not None:
        cmd.append(payload)
    subprocess.run(cmd)

    with os.fdopen(runtime_fd, 'rb') as f:
        data = f.read()

    with os.fdopen(mapfile_fd, 'r') as f:
        mapfile = f.read()

    os.close(linker_script_fd)

    return data, mapfile


class BadLink:
    def __init__(self, runtime, linker_script, unpacked_kernel,
                 direct_patching=False, payload=None):
        self._runtime = runtime
        self._linker_script = linker_script
        self._unpacked_kernel = Kernel(unpacked_kernel)
        self._payload = payload
        self._direct_patching = direct_patching
        temp_symbols = generate_lds(self._unpacked_kernel, want=None,
                                    direct_patching=self._direct_patching)
        test_link = link(runtime, temp_symbols, linker_script, payload)
        self._size = len(test_link[0])
        self._mapfile = test_link[1]

        # We are using the map file we get from the test link, not the final
        # artifact.
        # Shouldn't be an issue, just noting it!
        self._mapfile = self._extract()
        self._to_set = {}

    def get_key(self, key):
        return self._mapfile[key]

    def set_key(self, key, value):
        self._to_set[key] = value

    def get(self):
        """
        Return the data post linking
        """
        symbols = generate_lds(
            self._unpacked_kernel,
            want=min(WANT, self._size),
            direct_patching=self._direct_patching
        )
        for k, v in self._to_set.items():
            symbols[k] = v
        print(wrap_lds(symbols))
        data, _ = link(
            self._runtime, symbols, self._linker_script, payload=self._payload,
        )
        return bytearray(data)

    def size(self):
        return self._size

    def _extract(self):
        found = False
        res = {}
        for line in self._mapfile.split('\n'):
            ls = line.strip()
            if ls == 'Linker script and memory map':
                found = True
                continue
            elif ls == '/DISCARD/':
                found = False
                continue

            if not found:
                continue
            if ls == '':
                continue

            ls = ls.split()
            if len(ls) != 2:
                continue

            # filtering the sizes of sections.
            try:
                int(ls[1], 16)
                continue
            except Exception: # unsure which specific 
                pass

            res[ls[1]] = int(ls[0], 16)

        # first symbol
        offset = res['_uefi_entry']
        for key in res.keys():
            res[key] -= offset
        return res
