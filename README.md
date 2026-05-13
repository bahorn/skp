# SKP - Modern x86 Linux Kernel Patching

This is a PoC tool to patch x86 Linux kernel bzImages to load a kSHELF.
This is a modern version of the idea from Phrack 60-8 [1], but doing a very
different style of patches.

Supports 5.15+ for both UEFI and BIOS, tested up to 7.0.

Primarily tested with kernel images from Ubuntu, and my testing KConfig is
derived from the default Ubuntu configuration.
Other distros might do something that breaks this, though I hope not :)
Make sure ftrace is enabled and you have `CONFIG_REGULATOR` as that is used in
the initcall hook.

The payloads can be compiled with
[klude2](https://github.com/bahorn/klude2). Modify one of the samples in
`tools/klude2/src/sample` to change what it does.
All kernel symbols are supported, and they can work across kernel versions but
you are better off building the payload for your specific kernel.
There is a roughly 128KB space limitation for your payload, depending on method.
Some ways around that depending on kernel / boot method, but this is the general
limit.

I have set this up to not need you to provide a payload, as the default
behaviour is just to print some info during the kernels boot.
You can modify the code in `src/runtime/kshelf-loader/` if you want to do
anything more.

## Usage

Please read the source, as this is not something simple to use.

You will need to install the [`just` command runner](https://just.systems).

Help:
```
just --list
Available recipes:
    [Listing]
    default                                         # List Commands

    [build]
    clean                                           # Clean the Project
    patch-kernel kernel=env("SOURCE_KERNEL") output=patched_kernel payload=env("PAYLOAD", "") # Patch a kernel
    patch-with-payload path payload=default_payload # Patch a kernel based on the source tree provide, and build a payload for it from source.

    [dev]
    lint

    [run]
    gdb                                             # Connect to the GDB server
    run-bios                                        # Run a Kernel via BIOS
    run-grub-bios                                   # Run the kernel via a BIOS grub rescue images - *Can not be ran in parallel!*
    run-grub-uefi                                   # Run the Kernel via UEFI GRUB -  *Can not be ran in parallel!*
    run-uefi                                        # Run a Kernel via UEFI with OVMF

    [setup]
    easylkb version kconfig=(BASEDIR / "configs/test.KConfig") extra="" # Use easylkb to build a kernel
    get-grub-uefi                                   # Download the Ubuntu's UEFI build of GRUB
    get-rootfs                                      # Download OpenWRTs rootfs
    setup                                           # Install dependencies to build the project

    [testing]
    end-to-end path payload=default_payload         # End to end testing of a kernel tree, building the payload from source.
    end-to-end-batch test_kernel_list payload=default_payload
    test-batch test_kernel_list payload=env("PAYLOAD", "") # Test a list of kernels. This does not rebuild the payload for the given kernel.
```

To setup the virtualenv and dependencies:
```
just setup
```

Then patch a kernel with:
```
just patch-kernel path/to/kernel path/to/output path/to/payload
```

The payload can be omitted, and it will just print a confirmation during boot
which is useful for debugging.

For example:
```
just patch-kernel ./tools/easylkb/kernel/linux-6.8/arch/x86/boot/bzImage \
    ./samples/patched-kernel.bzimage ./tools/klude2/artifacts/payload.o
```

You can then the following to test it out:
* `just run-uefi`
* `just run-bios`
* `just run-grub-uefi`
* `just run-grub-bios`

(Those default to `./samples/patched-kernel.bzimage` for the kernel)

The default configuration runs the qemu monitor on port localhost:55555 and a
gdbserver on localhost:1234.
This can be disabled by refixing the command with `extra_qemu=""`,
e.g `just extra_qemu="" run-uefi`.

If you:
* need a rootfs, run `just get-rootfs` to download one from OpenWRT.
* Want to run this under uefi GRUB, run `just get-grub-uefi` to setup Ubuntu's
  UEFI GRUB (Note that the grub version you install limits which kernels you can
  boot!)

A build cache is in `intermediate/SHASUM_OF_KERNEL` which stores a copy of the
kernels kallsyms and internal ELF.

If you need a kernel, [easylkb](https://github.com/deepseagirl/easylkb) is
integrated, which you can use it via `just easylkb 6.8` and get a working 6.8
kernel to test with.
Adjust the version to try other versions, and you can also change the kconfig as
well.
The output kernel will be in
`./tools/easylkb/kernel/linux-VERSION/arch/x86/boot/bzImage`.
This uses my dev fork on easylkb, which has the optional feature to build the
kernel in a container and also provide point versions.

## Testing

If you want to test a batch of kernels and see if they all boot correctly with
the patch you can use the `just test-batch` command.

Create a file containing the paths to each kernel you want to test, then run
`just test-batch kernels.lst payload.bin` and it will use
`./tools/testing/verify.py` to tell you which kernels failed to boot.

A timeout of 30 seconds is used for each kernel, which might not be enough.
You can change it in `./tools/testing/test-batch.sh`.

An example list of kernels looks like:
```
./samples/kernels/vmlinuz-6.8.0-41-generic
./tools/easylkb/kernel/linux-6.10/arch/x86/boot/bzImage
./tools/easylkb/kernel/linux-6.9/arch/x86/boot/bzImage
./tools/easylkb/kernel/linux-6.0/arch/x86/boot/bzImage
```

If you want to test a given kernel tree with a specific payload, try something
like this:
```
just end-to-end ./tools/easylkb/kernel/linux-6.8/ ./tools/klude2/samples/nop
```

Or a batch with your specific payload:
```
just end-to-end-batch ./configs/test-kernels-path.list ./tools/klude2/samples/nop
```

(requires the paths to the kernel trees, not the bzImage).

### Debugging

There a few common things that break between kernel versions:
* Changes to the kernels PE header / structure.
* Symbols being changed (commonly breaking your final payloads).
* kallsyms changing, breaking vmlinux-to-elf for that versions.

To debug PE issues, I'd advise using PE-Bear as it shows color indicators when
something is wrong, e.g if a section is not fully mapped (which happens if the 
calculations for adding data to it are wrong).
Otherwise, using imhex with the PE pattern is good, this was the main tool to
help do development early on, or just readpe from your distros package manager
is useful enough.

Your payload will need some symbols, and assume structures look in specific way.
Make sure you built it against your target kernel!
Sometimes you can get away with using it across kernel versions, just hard to
know when it will break.
If its just a lack of a symbol there will be something printed to the kernel
log, but structure changes will be more insidious.

I'd advise doing sanity checks on the kallsyms output you get from
vmlinux-to-elf, as you can work out if the addresses look wrong.

You probably also want to search the kernels commit history, often not to hard
to find a likely issue there.

Very weird issues have occurred due to preemption in the kernel (specifically
the UEFI runtime hook breaking), so be mindful of that.
A bug that occurred probabilistically was due to this in 6.19, and the lack of
disabling preemption broke 5.15.

### Bisecting Kernels

**this section is a bit out of date**

You'll probably end up needing to bisect changes to determine which changes
broke things.

First, setup a script (`wrapper.sh`) in the directory of the kernel:
```
cd PATH_TO_SKP && ./tools/testing/bisect.sh $1 uefi
```

Then you can do a bisect like so:
```
export PAYLOAD=path_to_payload
git bisect start
git bisect old v5.15
git bisect new v5.16
git bisect run ./wrapper.sh `pwd`
```

Which should find the commit that introduced / fixed the issue in a hour or two.

The bisect.sh script does assume old is the one that causes the issue, and new
is the one where it is fixed.
You can change this behaviour by removing the `--invert` in
`./tools/testing/bisect.sh`

## Project Structure

* `tools/` - scripts / external projects. Covers klude2, easylkb, vmlinux-to-elf
  and random scripts for testing.
* `configs/` - kernel configs, the list of kernels to test against, and grub
  configs.
* `src/patch-bzimage` - the core, which modifies a kernel bzImage to run our
  payload.
* `src/runtime` - the code the will be patched in the kernel (except the payload
  you provide). This is built independent of the kernel version and is only
  properly linked at patching time by `patch-bzimage`.
* `src/skp.sh` - a wrapper script that unpacks kernels so they can be used with
  `patch-bzimage`. This is what is invoked by `just patch-kernel`.
* `Justfile` - Just is a command runner, that works better than using makefiles.
   You'll want to read this one to understand the project.

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
of larger sizes, while the direct patch only allows ~1MB, depending on the
kernel image (see `find_space()` in `src/patch-bzimage/generate_lds.py` where
it is at the time of writing set to 65kb) and also working on older kernel
versions as `ExitBootServices()` is called much earlier in the boot process.
The primary disadvantage is that you have to do a runtime hook, and the path is
separate from what the BIOS hook does, which is more unstable as it runs in a
weirder context (half interrupt/half normal).

The direct patch is probably what you should use in most cases however, but you
can disable it by running skp with `EXTRA_PATCH=--no-uefi-direct`.

This hook then runs the kSHELF loader and gets the module going.

### BIOS

This BIOS path installs a hook in code32_start (see advanced hooks in [3]),
which patches the code to jump to the decompressed kernel to then call our code
to patch the kernel.
We jump to our code by going to `0x100_000 + offset - start of .text`.

This is done as the kernel relocates itself at this point, and will cut off our
appended data from being accessed relatively.
But there remains the original mapping 0x100_000, which we can use if we set the
`pref_address` and disable relocation in the x86 boot protocol [3].

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

If the kernel is compiled with KASAN, the patch sometimes seems sometimes
trigger a `global-out-of-bounds`, when calling a function with one of the
payloads strings as an argument.
Noticed this only in 6.10, wasn't sure if there was some changes related to
KASAN here as my builds for 6.9 also had KASAN enabled.

## License

GPL2

PRs welcome, but please no LLM spam! This is an LLM-free project.

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
