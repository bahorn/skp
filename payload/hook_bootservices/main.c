/* UEFI ExitBootServices hook to patch the kernel.
 * Need to check how well this works with memory protection, as we are writing
 * to our own segement.
 * */
#include <efi.h>
#include <efilib.h>


// Want it pre-initialized
EFI_EXIT_BOOT_SERVICES orig_exitbootservices = 0x41424344;


EFI_STATUS exit_bootservices_hook(EFI_HANDLE ImageHandle, UINTN MapKey)
{
    //while (1) {}
    return orig_exitbootservices(ImageHandle, MapKey);
}


__attribute__ ((section(".text.start")))
void _start(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_BOOT_SERVICES *bootservices = SystemTable->BootServices;
    
    orig_exitbootservices = bootservices->ExitBootServices;
    bootservices->ExitBootServices = exit_bootservices_hook;
}
