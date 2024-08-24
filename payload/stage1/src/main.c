#include <elf.h>
#include <stddef.h>
#include <stdbool.h>
#include "main.h"
#include "../../../../klude2/artifacts/payload.h"

#define PAGE_SIZE 4096

unsigned long kallsyms_lookup_name(const char *name);
void *vmalloc(unsigned long size);
int _printk(const char *fmt, ...);
int set_memory_x(unsigned long addr, int numpages);
int set_memory_ro(unsigned long addr, int numpages);

size_t get_n_pages(size_t n);
bool do_relocs(void *elf);
int strcmp(const char *s1, const char *s2);

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
    Elf64_Rela *rela = NULL;
    Elf64_Sym *symtab = NULL;
    char *strtab = NULL;
    uint64_t relasz = 0;
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
        switch (ELF64_R_TYPE(rela[i].r_info)) {
            case R_X86_64_GLOB_DAT:
                /* symtab idx */
                int sym_idx = ELF64_R_SYM(rela[i].r_info);
                char *symname = strtab + symtab[sym_idx].st_name;
                unsigned long sym_addr = kallsyms_lookup_name(symname);
                _printk("relocating sym: %s\n", symname);
                to_patch = \
                    (unsigned long *)(elf + rela[i].r_offset);
                *to_patch = sym_addr + rela[i].r_addend;
                break;
            case R_X86_64_RELATIVE:
                _printk("relative relocation: %i\n", rela[i].r_addend);
                to_patch = \
                    (unsigned long *)(elf + rela[i].r_offset);
                *to_patch = elf + rela[i].r_addend;
                break;
            default:
                _printk("unknown relocation?\n");
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

/* process */
void run_elf(void *elf, size_t len)
{
    size_t size = get_virtualsize(elf);
    void *body = vmalloc(size);
    /* First copy the ELF to a new location */
    memset(body, 0, size);
    memcpy(body, elf, len);
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *) body;
    /* Apply the relocations by searching through the PHDRs for a PT_DYNAMIC */
    if (!do_relocs(body)) {
        return;
    }
    
    /* Go through the program headers to set correct page permissions for each
     * PT_LOAD */
    for (uint16_t curr_ph = 0; curr_ph < ehdr->e_phnum; curr_ph++) {
        Elf64_Phdr *phdr = body + ehdr->e_phoff  + curr_ph * ehdr->e_phentsize;
        if (phdr->p_type != PT_LOAD)
            continue;
        
        size_t size = get_n_pages(phdr->p_memsz);
        switch (phdr->p_flags & (PF_R | PF_W | PF_X)) {
            case PF_R | PF_W:
                /* Default case, nothing needs to be done */
                _printk("RW\n");
                break;

            case PF_R | PF_X:
                _printk("RX\n");
                /* Set RO, then make it executable */
                set_memory_ro((uint64_t) body + phdr->p_vaddr, size);
                set_memory_x((uint64_t) body + phdr->p_vaddr, size);
                break;

            default:
                _printk("Unsupported page permission\n");
                return;
        }
    }


    /* Transfer control */
    typedef void (*start_t)(void);
    _printk("Entrypoint: %lx\n", body + ehdr->e_entry);
    start_t start = (start_t)(body + ehdr->e_entry);

    start();
}


void main(void) {
    _printk("PATCHED KERNEL\n");
    run_elf(payload, payload_len);
    return;
}
