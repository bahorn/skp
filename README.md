# Modern Static Kernel Patching

This is a PoC tool to patch linux kernel bzImages to load a kSHELF.

This is a modern version of a the idea from Phrack 60-8 [1], but doing very
different style of patches.

This supports 5.15+ (beyond some vmalloc changes in 6.10) for the BIOS boot path
and 5.16+ for the UEFI runtime hook (due to a bug I haven't yet figured out in
older kernels).

## Usage

Please read the source, as this ain't a something simple to use.
This also uses the [`just` command runner](https://just.systems), which you will
need to sinstall.

Setup:
```
just setup
```

Will setup a virtualenv and the dependencies.

You need to activate the venv before moving on:
```
source .venv/bin/activate
```

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

You can then `just run-ovmf` or `just run-bios` to test it out.
The default configuration requires one of the following to start the VM:
* attaching gdb with `gdb -ex "target remote localhost:1234"`
* connecting to `localhost:55555` with netcat to start the virtual machine.

If you need a rootfs, run `just get-rootfs` to download one from OpenWRT.

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
