# Modern Static Kernel Patching

A bootkit called Pestilence.

## Strats

* Why not just replace the compressed Kernel
* * Big issue here is that extract_kernel comes after it.
* * Maybe not too big of a deal if we just update the offset used for the jump?
* Extend existing .text, add in our code, patch to make sure we have space.


Extend .text, place patcher code at end.
Hook just before we jump to the Kernel to jump to our patcher
Make sure we don't hit .bss, heap, whatever, adjust those in the code.
Fix checksums.


Patch to apply:
* hook init call to jump to kshelf loader


what if we put out patch at the start of 



6.8 changed how extract_kernel is called, still using rbp as output.




So actually tampering with startup_64 might be viable, then we replace the
compressed kernel and patch in our code to it.


.head.text -> just startup_64 and some others, we can find its end via looking
for the magic number for the compression. (currently zstd).
.rodata..compressed -> compressed blob
.text -> follows the compressed code.


so if we replace .rodata..compressed with a new kernel + update some values in
startup_64, should be fine?
problem is all the things in .data, .rodata, .bss




what about unified kernel images?
-> probably a second section?
