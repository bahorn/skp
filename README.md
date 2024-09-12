# Modern Static Kernel Patching

This is a PoC tool to patch x86 Linux kernel bzImages to load a kSHELF.

This is a modern version of a the idea from Phrack 60-8 [1], but doing very
different style of patches.

This supports 5.15+ (beyond some vmalloc changes in 6.10) for the BIOS boot path
and 5.16+ for the UEFI runtime hook (due to a bug I haven't yet figured out in
older kernels).

## Usage

Please read the source, as this ain't a something simple to use.
This also uses the [`just` command runner](https://just.systems), which you will
need to install.

Setup:
```
just setup
```

This will setup a virtualenv and the dependencies.

Then you need to the the following environment variables:
```
export SOURCE_KERNEL=./sample-kernels/vmlinuz-6.8.0-41-generic
export PAYLOAD=../artifacts/main.bin
```

You can set the following envvars:
* `PATCHED_KERNEL` is the output kernel bzImage
* `SOURCE_KERNEL` is the kernel image you are modifying,
* `ROOTFS` is a rootfs to use for testing.
* `PAYLOAD` is the kSHELF you want to load that was built with klude2.
* `OVMFFW` is the OVMF firmware build you want to run in your tests.

(You can also set these by an a per command basis, see the Justfile for internla
names, then set those before the command you are trying to run!)

With those, you can run `just patch-kernel` and the patched kernel will be
created.
There is also support for two positional arguments to change the source kernel
and payload.

You can then `just run-ovmf`, `just run-bios` or `just run-grub-uefi` to test it
out.
The default configuration requires one of the following to start the VM:
* attaching gdb with `gdb -ex "target remote localhost:1234"`
* connecting to `localhost:55555` with netcat to start the virtual machine.

If you:
* need a rootfs, run `just get-rootfs` to download one from OpenWRT.
* want to run this under uefi GRUB, run `just get-grub` to setup Ubuntu's GRUB
  (Note that the grub version you install limits which kernels you can boot!)

A build cache is in `intermediate/SHASUM_OF_KERNEL` which stores a copy of the
kernels kallsyms and internal ELF.

If you need a kernel, easylkb is integrated, so you can use it like
`just easylkb 6.8` and get a working 6.8 kernel to test with.
Adjust the version to try other versions, and you can also change the kconfig as
well.
The output kernel will be in
`./tools/easylkb/kernel/linux-VERSION/arch/x86/boot/bzImage`.

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
This hook can do one of two things:
* Setup a hook for the Runtime function `GetVariable()` which should be called
  during the boot by most kernels.
* Directly patch the kernel as it is decompressed at this point on post 6.6
  kernels.

The runtime hook has some advantages in terms of it allowing the use of payloads
of arbitary sizes, while the direct patch only allows ~1MB, depending on the
kernel image (see `src/scripts/find_space.py` where it is at the time of writing
set to 65kb) and also working on older kernel versions as `ExitBootServices()`
is called much earlier in the boot process.
The primary disavantage is that you have to do a runtime hook, and the path is
seperate from what the BIOS hook does.

The runtime hook is probably what you should use in most cases however.
You can force it to be always used by unseting `DIRECT_PATCHING` in 
`src/runtime/stage1-uefi-bootservices-hook/Makefile`.

This hook then runs the kSHELF loader and gets the module going.

### BIOS

This BIOS path installs a hook in code32_start (see advanced hooks in [3]),
which patches the code to jump to the decompressed kernel to then call our code
to patch the kernel.
We jump to our code by going to `0x100_000 + offset - start of .text`.

This is done as page tables are setup at this point, and will cut off our
appended data from being accessed relatively.
But there remains the mapping at 0x100_000 we can still use if we disable kernel
relocation, which is where we call our patcher from.

Our code here will then copy the remaining data into a known cavity in the
kernel image, and hook an initcall to transfer control to it.

## Background / Notes

This is not the first attempt at this sort of thing.
The original paper in Phrack 60-8 [1] is the first attempt of this that I'm
aware of.
More recently, I'm aware of two projects [4][5] (found via [6]) that did this
for non-x86 kernel images, aiming to replace the kernel and adjust various
offsets.
I looked at doing that sort of approach, but ended up deciding it was easier to
go my route to support a wider variety of kernel versions.

The x86 boot path has undergone a bit of work in 2023 [7][8], which made a lot
of good changes.
The PE header got reworked which made adding an extra section easier (though you
can just remove .reloc in older images, which this project does).

My code does assume my added section is writable, to use global variables, which
might cause issues with some UEFI firmware.

Kernel Images do include their own checksum, as part of build.c, but AFAIK
nothing verifies it so I did not bother reimplementing it.

## License

GPL2

## References

* [1] http://phrack.org/issues/60/8.html#article
* [2] https://github.com/marin-m/vmlinux-to-elf
* [3] https://www.kernel.org/doc/html/v6.8/arch/x86/boot.html
* [4] https://jamchamb.net/2022/01/02/modify-vmlinuz-arm.html
* [5] https://github.com/Caesurus/CTF_Writeups/blob/main/2024-04-zImageKernelPatch/README.MD
* [6] https://stackoverflow.com/questions/76571876/how-to-repack-vmlinux-elf-back-to-bzimage-file
* [7] https://lore.kernel.org/all/20230915171623.655440-10-ardb@google.com/
* [8] https://lore.kernel.org/all/20230807162720.545787-1-ardb@kernel.org/
