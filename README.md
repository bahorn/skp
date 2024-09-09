# Modern Static Kernel Patching

This is a PoC tool to patch linux kernel bzImages to load a kSHELF.

This is a modern version of a the idea from Phrack 60-8 [1], but doing very
different style of patches.

This supports 5.15+ (beyond some vmalloc changes in 6.10) for the BIOS boot path
and 5.16+ for the UEFI runtime hook (due to a bug I haven't yet figured out in
older kernels).

## Usage

Please read the source, as this ain't a something simple to use.

Setup:
```
make setup
```

Will setup a virtualenv and the dependencies.

You need to activate the venv before moving on:
```
source .venv/bin/activate
```

Then, you need to adjust the kernel image defined in the `Makefile` to be
your kernel, and update the payload.

Then `make run-ovmf` or `make run-bios` to test it out.

## Techniques

This modifies two paths to boot the kernel.
Via UEFI and via the traditional BIOS bootloaders.
Both routes will load a kSHELF, which is a type of kernel module I developed to
avoid having a module loaded.

### Information Gathering

I use `vmlinux-to-elf`[2] to extract kernel symbols and their offsets, and
unpack the kernel to search for a cavity to use in the BIOS path.
This gets passed down to the build process for the runtime component as that
needs to know where to place the payload in the kernel and also where symbols
like `kallsyms_lookup_name()` are relative to it.

### UEFI

First, we hook the UEFI entrypoint with code that will install a hook on
ExitBootServices().
When this hook is ran, it setups up a hook for the UEFI runtime function
GetVariable(), which is called during boot by most kernels.

This hook then runs the kSHELF loader and gets the module going.

### BIOS

This BIOS path installs a hook in code32_start[3], which patches the code to jump
to the decompressed kernel to then call our code to patch the kernel.
We jump to our code by going to 0x100_000 + offset to our code.

This is done as page tables are setup at this point, and will cut off our
appended data from being accessed relatively.
But there remains the mapping at 0x100_000 we can still use if we disable kernel
relocation, which is where we call our patcher from.

Our code here will then copy the remaining data into a known cavity in the
kernel image, and hook an initcall to transfer control to it.

## License

GPL2

## References

* [1] http://phrack.org/issues/60/8.html#article
* [2] https://github.com/marin-m/vmlinux-to-elf
* [3] https://www.kernel.org/doc/html/v6.8/arch/x86/boot.html
