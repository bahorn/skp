# Modern Static Kernel Patching

A PoC tool to patch linux kernel images to add in a kSHELF, as an PoC approach to
implement a bootkit.

Doesn't touch UEFI, no secureboot bypasses here.

## Usage

read the source, this ain't a something simple to use.

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

Both the UEFI and BIOS paths are patched into the kernel.
Both routes will load a kSHELF, which is a type of kernel module I developed to
avoid having a module loaded.
It is just vmalloc()'d in.


### UEFI

First, we hook the UEFI entrypoint to install a hook on ExitBootServices(),
which will then either directly patch the kernel post decompression (post 6.6
kernels) or install a UEFI runtime hook that will be ran during the kernels
boot.


### BIOS

This case we patch the code that is called right after decompression, and make
it jump to 0x100_000 + offset to our code.

We have to do this as page tables are setup at that point, and will cut off our
appended data from being accessed relatively.

But there remains the mapping at 0x100_000 we can still use, which is where we
call our patcher from.

Our code here will then copy the remaining data into a known cavity in the
kernel image.


### Layout

We merge all our stages into a single blob that will get appended to the kernel
image, correcting the PE/COFF headers to be bootable via UEFI.
