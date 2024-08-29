/* UEFI ExitBootServices hook to patch the kernel.
 * Need to check how well this works with memory protection, as we are writing
 * to our own segement.
 * */
#include <efi.h>
#include <efilib.h>

// How far we want to go looking for the entrypoint.
#define MAX_DEPTH 4096


// Want it pre-initialized
EFI_EXIT_BOOT_SERVICES orig_exitbootservices = 0x41424344;
EFI_SYSTEM_TABLE *systable = 0x41424344;
EFI_BOOT_SERVICES *bootservices = 0x41424344;
int called = 0;



int compare(char a, char b)
{
    return a == b;
}


/* Check if this address is mapped, and a valid entrypoint */
int check_address(void *addr)
{
    char *to_test = addr;

    // Some fixed values we know from startup_32
    if (!compare(to_test[0], 0xfc)) {
        return 0;
    }

    if (!compare(to_test[1], 0x0f)) {
        return 0;
    }

    // Now startup_64 for our actual entrypoint
    if (!compare(to_test[0x80], 0x49)) {
        return 0;
    }

    if (!compare(to_test[0x81],0x89)) {
        return 0;
    }

    if (!compare(to_test[0x82], 0xf7)) {
        return 0;
    }

    return 1;
}

/* Apply our kernel patches */
void apply_patch(void *addr)
{

}


EFI_STATUS exit_bootservices_hook(EFI_HANDLE ImageHandle, UINTN MapKey)
{
    // Could be potentially called twice, so deal with that.
    if (called == 1) {
        goto done;
    }
    called = 1;
    // We are using this to read out of bounds and check the contents of the
    // stack.
    void *test = &ImageHandle;

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
    
    bootservices->AllocatePool(
        EfiBootServicesData,
        mapsize + descriptorsize * 2,
        (void **)&map
    );
    mapsize = mapsize + descriptorsize * 2;

    bootservices->GetMemoryMap(
        &mapsize,
        map,
        &mapkey,
        &descriptorsize,
        &descriptorversion
    );

    int count = mapsize / descriptorsize;
    count += 2;
    int j = 0;
    /* Now we have the memory map, lets hunt */
    for (int i = 0; i < count; i++) {
        EFI_MEMORY_DESCRIPTOR curr = map[i];
        if (curr.Type != 1) {
            continue;
        }

        if (check_address(curr.PhysicalStart)) {
            /* + 0x80 as that is startup_64 */
            apply_patch(curr.PhysicalStart + 0x80);
            goto done;
        }
    }

    // maybe look at setting up a runtime services to keep some code alive after
    // this.
done:
    if (map != NULL) {
        bootservices->FreePool(&map);
    }
    return orig_exitbootservices(ImageHandle, MapKey);
}


__attribute__ ((section(".text.start")))
void _start(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    bootservices = SystemTable->BootServices;
    systable = SystemTable;
    
    orig_exitbootservices = bootservices->ExitBootServices;
    bootservices->ExitBootServices = exit_bootservices_hook;
}
