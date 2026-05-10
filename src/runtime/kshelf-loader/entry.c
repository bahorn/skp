/* Our runtime hook */
#include <elf.h>
#include <stddef.h>
#include <stdbool.h>

#define PAGE_SIZE 4096

#define LOOKUP(SYM) SYM = (SYM ## _t) kallsyms_lookup_name_(#SYM)

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef int (*_printk_t)(const char *fmt, ...);
typedef void *(*vmalloc_t)(unsigned long size);
typedef int *(*set_memory_x_t)(unsigned long addr, int numpages);
typedef int *(*set_memory_ro_t)(unsigned long addr, int numpages);
typedef int (*regulator_init_complete_t)(void);

extern const uintptr_t kallsyms_lookup_name \
    __attribute__((visibility("hidden")));
kallsyms_lookup_name_t kallsyms_lookup_name_ = \
    (kallsyms_lookup_name_t) &kallsyms_lookup_name;

_printk_t _printk;
vmalloc_t vmalloc;
set_memory_x_t set_memory_x;
set_memory_ro_t set_memory_ro;
regulator_init_complete_t regulator_init_complete;

size_t get_n_pages(size_t n);
bool do_relocs(void *elf);
int strcmp(const char *s1, const char *s2);

__attribute__((weak)) unsigned char payload[0];
__attribute__((weak, section(".data"))) unsigned int payload_len = 0;


// #define PRINTK(...) ((void)0)
#define PRINTK(...) _printk(__VA_ARGS__)

/* Basic stolen strcmp implementation:
 * https://stackoverflow.com/questions/34873209/implementation-of-strcmp
 */
int strcmp(const char *s1, const char *s2)
{
    while(*s1 && (*s1 == *s2))
    {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

void *memcpy(void *dest, const void *src, size_t n)
{
    char *d = (char *)dest;
    char *s = (char *)src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dest;
}


void *memset(void *s, int c, size_t n)
{
    char *d = (char *)s;
    for (size_t i = 0; i < n; i++) {
        d[i] = 0;
    }
    return s;
}

/* Maps a size to the number of pages */
size_t get_n_pages(size_t n)
{
    size_t i = (n / PAGE_SIZE);
    if ((n % PAGE_SIZE) > 0) {
        i += 1;
    }
    return i;
}


/* ELF LOADER */

bool do_relocs(void *elf)
{
    Elf64_Dyn *dyn = NULL;
    Elf64_Rela *rela = NULL;
    Elf64_Sym *symtab = NULL;
    char *strtab = NULL;
    uint64_t relasz = 0;
    int dynamic_tags = 0;
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *) elf;
    for (uint16_t curr_ph = 0; curr_ph < ehdr->e_phnum; curr_ph++) {
        Elf64_Phdr *phdr = elf + ehdr->e_phoff  + curr_ph * ehdr->e_phentsize;
        if (phdr->p_type != PT_DYNAMIC) continue;
        dyn = elf + phdr->p_offset;
        dynamic_tags = phdr->p_filesz / sizeof(Elf64_Dyn); 
        break;
    }
    if (dyn == NULL) return true;

    /* Now we iterate through .dynamic looking for strtab, symtab, rela */
    for (int i = 0; i < dynamic_tags; i++) {
        Elf64_Dyn *tag = &dyn[i];
        switch (tag->d_tag) {
            case DT_NULL:
                goto dt_end;

            case DT_RELA:
                rela = elf + tag->d_un.d_val;
                break;

            case DT_RELASZ:
                relasz = (uint64_t)tag->d_un.d_val;
                break;

            case DT_STRTAB:
                strtab = elf + tag->d_un.d_val;
                break;

            case DT_SYMTAB:
                symtab = elf + tag->d_un.d_val;
                break;
        }
    }
dt_end:
    if (rela == NULL || symtab == NULL || strtab == NULL)
        return false;

    relasz /= sizeof(Elf64_Rela);
    /* Now we iterate through the RELA */
    for (int i = 0; i < relasz; i++) {
        unsigned long *to_patch;
        int sym_idx = 0;
        char *symname = NULL;
        unsigned long sym_addr = 0;

        switch (ELF64_R_TYPE(rela[i].r_info)) {
            case R_X86_64_GLOB_DAT:
                /* symtab idx */
                sym_idx = ELF64_R_SYM(rela[i].r_info);
                symname = strtab + symtab[sym_idx].st_name;
                sym_addr = kallsyms_lookup_name_(symname);
                PRINTK("relocating sym: %s\n", symname);
                to_patch = \
                    (unsigned long *)(elf + rela[i].r_offset);
                *to_patch = sym_addr + rela[i].r_addend;
                break;
            case R_X86_64_RELATIVE:
                PRINTK("relative relocation: %lli\n", rela[i].r_addend);
                to_patch = \
                    (unsigned long *)(elf + rela[i].r_offset);
                *to_patch = (unsigned long)elf + rela[i].r_addend;
                break;
            case R_X86_64_COPY:
                /* symtab idx */
                sym_idx = ELF64_R_SYM(rela[i].r_info);
                symname = strtab + symtab[sym_idx].st_name;
                sym_addr = kallsyms_lookup_name_(symname);
                PRINTK(
                    "copy sym: %s (%lli bytes)\n",
                    symname, symtab[sym_idx].st_size
                );
                to_patch = \
                    (unsigned long *)(elf + rela[i].r_offset);
                memcpy(
                    to_patch,
                    (void *)sym_addr,
                    symtab[sym_idx].st_size
                );
                break;
            default:
                PRINTK("unknown relocation?\n");
                return false;
        }
    }

    return true;
}

/* Compute the size we actually need */
size_t get_virtualsize(void *elf)
{
    size_t res = 0;
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *) elf;
    for (uint16_t curr_ph = 0; curr_ph < ehdr->e_phnum; curr_ph++) {
        Elf64_Phdr *phdr = elf + ehdr->e_phoff  + curr_ph * ehdr->e_phentsize;
        if (phdr->p_type != PT_LOAD) continue;
        res += get_n_pages(phdr->p_memsz) * PAGE_SIZE;
    }
    return res;
}

void run_tha_fun(void (*fun)(void))
{
    fun();
}

/* process */
void run_elf(void *elf, size_t len)
{
    typedef void (*start_t)(void);
    start_t start;
    Elf64_Ehdr *ehdr; 
    Elf64_Phdr *phdr;
    size_t size = get_virtualsize(elf);
    void *body = vmalloc(size);
    /* First copy the ELF to a new location */
    memset(body, 0, size);
    memcpy(body, elf, len);

    ehdr = (Elf64_Ehdr *) body;
    /* Apply the relocations by searching through the PHDRs for a PT_DYNAMIC */
    if (!do_relocs(body)) {
        return;
    }

    /* Go through the program headers to set correct page permissions for each
     * PT_LOAD */
    for (uint16_t curr_ph = 0; curr_ph < ehdr->e_phnum; curr_ph++) {
        phdr = body + ehdr->e_phoff  + curr_ph * ehdr->e_phentsize;
        if (phdr->p_type != PT_LOAD)
            continue;

        size = get_n_pages(phdr->p_memsz);
        switch (phdr->p_flags & (PF_R | PF_W | PF_X)) {
            case PF_R | PF_W:
                /* Default case, nothing needs to be done */
                PRINTK("RW\n");
                break;

            case PF_R | PF_X:
                PRINTK("RX\n");
                /* Set RO, then make it executable */
                set_memory_ro((uint64_t) body + phdr->p_vaddr, size);
                set_memory_x((uint64_t) body + phdr->p_vaddr, size);
                break;

            default:
                PRINTK("Unsupported page permission\n");
                return;
        }
    }


    /* Transfer control */
    PRINTK("Entrypoint: %lx\n", body + ehdr->e_entry);
    start = (start_t)(body + ehdr->e_entry);

    run_tha_fun(start);
}

/* Takes just the address of the _text section */
__attribute__ ((section(".text.start")))
int _kshelf_loader(unsigned long text, int via_initcall)
{
    int res = 0;
    // have to relocate it
    kallsyms_lookup_name_ = \
        (kallsyms_lookup_name_t) (text + (void *)kallsyms_lookup_name_);
    LOOKUP(_printk);
    LOOKUP(vmalloc);

    PRINTK("PATCHED KERNEL\n");

    /* vmalloc became a macro in 6.10, so working around that. */
    if (vmalloc == NULL) {
        // skips any alloc hooks.
        vmalloc = (vmalloc_t) kallsyms_lookup_name_("vmalloc_noprof");
    }

    LOOKUP(set_memory_ro);
    LOOKUP(set_memory_x);

    if (vmalloc == NULL || set_memory_ro == NULL || set_memory_x == NULL) {
        PRINTK("Can't get Symbol?\n");
        return res;
    }

    /* If we are called via a patched initcall, we need to call it back */
    if (via_initcall) {
        PRINTK("Called via initcall\n");
        regulator_init_complete = 
            (regulator_init_complete_t) kallsyms_lookup_name_(
                    "regulator_init_complete");
        res = regulator_init_complete();
    } else {
        PRINTK("Called via UEFI Runtime hook\n");
    }

    PRINTK("payload_len: %i\n", payload_len);
    if (payload_len > 0) {
        PRINTK("Running payload\n");
        run_elf(payload, payload_len);
    } else {
        PRINTK("No payload defined\n");
    }
    return res;
}
