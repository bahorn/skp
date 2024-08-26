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


### UEFI

(only kernels >6.6 currently)


Creates a new PE section called .patch, and expands the previous one to make the
raw size match the virtual size.

Then it patches code that jumps to the kernel right after decompression.
We apply our kernel patches here, then jump to it.


### BIOS

This case we patch the code that is called right after decompression, and make
it jump to 0x100_000 + offset to our code.

We have to do this as page tables are setup at that point, and will cut off our
appended data from being accessed relatively.

But there remains the mapping at 0x100_000 we can still use, which is where we
call our patcher from.


## Notes

Heavily relies on pattern matching ASM, some from compilers.
Would rather not, but kinda had to in some cases.

There are edge cases! This will make boxes unbootable if you actually try to use
it!
