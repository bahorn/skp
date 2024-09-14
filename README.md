# SKP - Modern x86 Linux Kernel Patching

This is a PoC tool to patch x86 Linux kernel bzImages to load a kSHELF.
This is a modern version of a the idea from Phrack 60-8 [1], but doing a very
different style of patches.

This supports 5.15+ for the BIOS boot path and 5.16+ for the UEFI runtime hook
(due to a bug I haven't yet figured out in older kernels).

Primarily tested with kernel images from Ubuntu, and my testing KConfig is
derived from the default Ubuntu configuration.
Other distros might do something that breaks this, though I hope not :)
Make sure ftrace is enabled and you have `CONFIG_REGULATOR` as that is used in
the initcall hook.

Currently relying on a private repo for the payloads, which will be GPL2'd soon
(tm).
You can probably get by with my older public version of
[klude](https://github.com/bahorn/klude), just know I have fixed the major bugs
in it now.

## Usage

Please read the source, as this is not something simple to use.

You will need to install the [`just` command runner](https://just.systems).

Help:
```
Available recipes:
    clean         # Clean the Project
    default       # List Commands
    easylkb version kconfig=(BASEDIR / "configs/test.KConfig") # Use easylkb to build a kernel
    get-grub-uefi # Download the Ubuntu's UEFI build of GRUB
    get-rootfs    # Download OpenWRTs rootfs
    patch-kernel kernel=env("SOURCE_KERNEL") payload=env("PAYLOAD") # Patch a kernel
    run-bios      # Run a Kernel via BIOS
    run-grub-bios # BIOS grub
    run-grub-uefi # Run the Kernel via UEFI GRUB
    run-ovmf      # Run a Kernel via UEFI with OVMF
    setup         # Install dependencies to build the project
```


To setup the virtualenv and dependencies:
```
just setup
```

Then you need to the the following environment variables before you can patch a
kernel:
```
export SOURCE_KERNEL=./sample-kernels/vmlinuz-6.8.0-41-generic
export PAYLOAD=../artifacts/main.bin
```

The following envvars exist:
* `PATCHED_KERNEL` is the output kernel bzImage
* `SOURCE_KERNEL` is the kernel image you are modifying,
* `ROOTFS` is a rootfs to use for testing.
* `PAYLOAD` is the kSHELF you want to load that was built with klude2.
* `OVMFFW` is the OVMF firmware build you want to run in your tests.
* `EXTRA_PATCH` is flags to src/patch-bzimage. You can disable uefi and bios
  patching with `--no-uefi` and `--no-bios` respectively.
* `EXTRA_STAGE2_DEFINE` can be used to unset the DIRECT_PATCHING feature.

(You can also set these by an a per command basis, see the Justfile for internal
names, then set those before the command you are trying to run!)

With those, you can run `just patch-kernel` and the patched kernel will be
created.
There is also support for two positional arguments to change the source kernel
and payload instead of via the envvars.

You can then the following to test it out:
* `just run-ovmf`
* `just run-bios`
* `just run-grub-uefi`
* `just run-grub-bios`

The default configuration requires one of the following to start the VM:
* attaching gdb with `gdb -ex "target remote localhost:1234"`
* connecting to `localhost:55555` with netcat to start the virtual machine.

If you:
* need a rootfs, run `just get-rootfs` to download one from OpenWRT.
* want to run this under uefi GRUB, run `just get-grub-uefi` to setup Ubuntu's
  UEFI GRUB (Note that the grub version you install limits which kernels you can
  boot!)

A build cache is in `intermediate/SHASUM_OF_KERNEL` which stores a copy of the
kernels kallsyms and internal ELF.

If you need a kernel, easylkb is integrated, which you can use it via
`just easylkb 6.8` and get a working 6.8 kernel to test with.
Adjust the version to try other versions, and you can also change the kconfig as
well.
The output kernel will be in
`./tools/easylkb/kernel/linux-VERSION/arch/x86/boot/bzImage`.

## Techniques

This modifies two paths to boot the kernel.
Via UEFI and by the traditional BIOS bootloaders.
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
You can force it to be always used by unseting `DIRECT_PATCHING` in the envvar.

This hook then runs the kSHELF loader and gets the module going.

### BIOS

This BIOS path installs a hook in code32_start (see advanced hooks in [3]),
which patches the code to jump to the decompressed kernel to then call our code
to patch the kernel.
We jump to our code by going to `0x100_000 + offset - start of .text`.

This is done as page tables are setup at this point, and will cut off our
appended data from being accessed relatively.
But there remains the mapping at 0x100_000, which we can use if we set the
`pref_address` in the x86 boot protocol [3].

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

I do think the approach to get transfer control to the appended code in Phrack
60-8 is a bit bizare, as I went and reviewed kernels from that era and the
initcall approach did exist back then.
Would have made far more sense to use it than modify the syscall table.

Like the article I didn't bother removing the bss clearing code, as I just
appended 2 extra pages of null bytes to fill up bss, which worked fine with this
technique as it doesn't need to survive the whole boot process.
Those do get corrupted on older kernels in the BIOS bootpath though.

The x86 boot path has undergone a bit of work in 2023 [7][8], which made a lot
of good changes.
The PE header got reworked which made adding an extra section easier (though you
can just remove .reloc in older images, which this project does).

The code does assume the added section is writable, to use global variables,
which might cause issues with some UEFI firmware.
The recent kernel changes were meant to avoid them existing in the kernel.

Kernel Images do include their own checksum, as part of build.c, but AFAIK
nothing verifies it so I did not bother reimplementing it.

One thing I find a bit confusing is that the `pref_address` in the x86 boot
protocol is meant to be where the kernel is relocated to.
On modern kernels it is set to 0x1_000_000, but it was fine for me to lower it
down to 0x100_000.
GRUB does use it if the relocatable flag (otherwise 0x100_000 is used) is set
but I got away without it being changed with the default `-kernel` flag in qemu
with it always using 0x100_000.
I believe qemu ignoring this is a bug, and GRUB always using 0x100_000 if the
kernel isn't relocatable is wrong as well as it seems to contradict [3]:

> This field, if nonzero, represents a preferred load address for the kernel.
> A relocating bootloader should attempt to load at this address if possible.
>
> A non-relocatable kernel will unconditionally move itself and to run at this
> address.

Though reading that, it sounds like the kernel is relocating itself to do
in-place decompression, which matches up with
`arch/x86/boot/compressed/head_64.S` (lines 310 to 450 in the 6.10 tree).
So maybe GRUB is doing the right thing?

If you care about infecting LKMs, I did a seperate project reimplementing
another old phrack article that can do that. [9]

I am obviously not the first person to come up with hooking a runtime service.
pcileech, a project for performing DMA attacks, uses it to target older kernel
versions [10].
It finds `kallsyms_lookup_name()` in that shellcode, which is what you should do
if you want to make the patching code smaller and not require using
`vmlinux-to-elf`.

On my remaining list todo is the following:
* Code cleanup, src/patch-bzimage is a bit of a mess right now.
* Figure out why 5.15 segfaults with the Runtime hook. I need to git bisect a
  ton of kernels. Doing a vfs hook like pcileech might be a suitable way of
  fixing this.
* Maybe support older kernels. Unsure if I'll bother, as the issue is dealing
  with things like symbols being renamed, etc. I only ever want to care about
  kernels released in the last 5 years. 20.04 is the furthest I want to go back
  to.
* A proper writeup.

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
* [9] https://github.com/bahorn/lkm-infect/
* [10] https://github.com/ufrisk/pcileech/blob/master/pcileech_shellcode/lx64_stage2_efi.asm
