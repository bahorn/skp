"""
Our main, implementing the argument parser and workflow.
"""
import argparse
from add_data import add_data
from badlink import BadLink
from pe import PERemoveSig, PECheckSumFix
from remove_reloc import remove_reloc
from generate_lds import find_space, find_symbols
from consts import WANT, SYMBOLS


def patch_kernel(args):
    """
    Actually patch the kernel
    """
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
    with open(args.linker_script) as f:
        linker_script = f.read()

    badlink_payload = BadLink(
        args.runtime,
        kallsyms=args.kallsyms,
        linker_script=linker_script,
        unpacked_kernel=args.unpacked_kernel,
        payload=args.payload,
    )
    a = add_data(
        a,
        badlink_payload,
        apply_bios_patch=args.no_bios,
        apply_uefi_patch=args.no_uefi
    )

    # Checksum fixes for sanity
    # need to fix the bzImage checksum. Nothing really checks it, but lets do
    # it for completenes.
    # Modern kernel images don't seem to do this anymore and just set it to 0!
    last = PECheckSumFix(a).fix()
    with open(args.patched_kernel, 'wb') as f:
        f.write(last)


def debug_kernel(args):
    """
    Display debug information to help figure out details to improve this tool.

    Not for normal users!
    """
    # We need to have space to find a basic test case if we have any chance of
    # this kernel being patchable.
    print('space', find_space(args.unpacked_kernel, want=WANT))
    # This broke on 7.0 when the memory layout changed, causes negative symbols.
    for symbol, value in find_symbols(args.kallsyms, SYMBOLS).items():
        print('*', symbol, value, value < 0)


def main():
    parser = argparse.ArgumentParser(
        prog='patch-bzimage',
        description='Patches kernel bzImages',
    )

    subparsers = parser.add_subparsers(help="Commands", dest='command')

    patch = subparsers.add_parser('patch', help='Patch the kernel')
    patch.add_argument('source_kernel')
    patch.add_argument('unpacked_kernel')
    patch.add_argument('kallsyms')
    patch.add_argument('runtime')
    patch.add_argument('linker_script')
    patch.add_argument('patched_kernel')
    patch.add_argument('--payload', default=None)
    patch.add_argument('--no-bios', action='store_false')
    patch.add_argument('--no-uefi', action='store_false')


    debug = subparsers.add_parser('debug', help='Development debug info')
    debug.add_argument('unpacked_kernel')
    debug.add_argument('kallsyms')

    args = parser.parse_args()

    match args.command:
        case 'patch':
            patch_kernel(args)
        case 'debug':
            debug_kernel(args)
        case _:
            parser.print_help()


if __name__ == "__main__":
    main()
