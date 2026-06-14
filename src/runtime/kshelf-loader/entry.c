/* The kSHELF loader, running in a few contexts. */
#include <elf.h>
#include <stddef.h>
#include <stdbool.h>

#define PAGE_SIZE 4096
// 0x200 is unused in recent kernels, but nothing complains if you set it.
// so we can support all the kernels by just doing this.
#define GFP_ATOMIC 0x800 | 0x200 | 0x20

#define DEFSYM(SYM, RETTYPE, ARGS) \
        typedef RETTYPE (* SYM ## _t)ARGS; \
        SYM ## _t SYM

#define LOOKUP_RAW(SYM, VALUE) SYM = (SYM ## _t) VALUE
#define LOOKUP(SYM) SYM = (SYM ## _t) kallsyms_lookup_name_(#SYM)
#define LOOKUP_ALT(SYM, ALT) SYM = (SYM ## _t) kallsyms_lookup_name_(#ALT)

// We have to handle this a bit differently as the offset is passed in via the
// linker step.
extern const uintptr_t kallsyms_lookup_name \
    __attribute__((visibility("hidden")));

DEFSYM(kallsyms_lookup_name_, unsigned long, (const char *name)) = \
    (kallsyms_lookup_name__t) &kallsyms_lookup_name;
DEFSYM(_printk, int, (const char *fmt, ...));
DEFSYM(kmalloc, void *, (unsigned long size, unsigned int));
DEFSYM(set_memory_x, int *, (unsigned long addr, int numpages));
DEFSYM(set_memory_ro, int *, (unsigned long addr, int numpages));
DEFSYM(regulator_init_complete, int, (void));
DEFSYM(execute_in_process_context, bool, (void *wq, void *work));
DEFSYM(irq_enter_rcu, void, (void));
DEFSYM(irq_exit_rcu, void, (void));

void *wq = NULL;

size_t get_n_pages(size_t n);
bool do_relocs(void *elf);
int strcmp(const char *s1, const char *s2);

typedef void (*start_t)(void);
start_t start = NULL;

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

/* process */
bool setup_elf(void *elf, size_t len)
{
    Elf64_Ehdr *ehdr; 
    Elf64_Phdr *phdr;
    size_t size = get_virtualsize(elf);
    /* we *should* get a page aligned allocation:
    > The address of a chunk allocated with kmalloc is aligned to at least
    > ARCH_KMALLOC_MINALIGN bytes. For sizes which are a power of two, the
    > alignment is also guaranteed to be at least the respective size. For
    > other sizes, the alignment is guaranteed to be at least the largest
    > power-of-two divisor of the size.
    */
    void *body = kmalloc(size, GFP_ATOMIC);
    /* First copy the ELF to a new location */
    memset(body, 0, size);
    memcpy(body, elf, len);

    ehdr = (Elf64_Ehdr *) body;
    /* Apply the relocations by searching through the PHDRs for a PT_DYNAMIC */
    if (!do_relocs(body)) {
        return false;
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
                return false;
        }
    }

    /* Transfer control */
    PRINTK("Entrypoint: %lx\n", body + ehdr->e_entry);
    start = (start_t)(body + ehdr->e_entry);
    return true;
}

/* Resolve the required symbols for run_elf() */
bool resolve_required(void)
{
    LOOKUP(kmalloc);
    // one of these SHOULD work...
    if (kmalloc == NULL) {
        LOOKUP_ALT(kmalloc, __kmalloc);
    }
    if (kmalloc == NULL) {
        // unlikely to be the case, as this is primary an inline function.
        LOOKUP_ALT(kmalloc, kmalloc_noprof);
    }
    if (kmalloc == NULL) {
        LOOKUP_ALT(kmalloc, __kmalloc_noprof);
    }

    LOOKUP(set_memory_ro);
    LOOKUP(set_memory_x);
    if (kmalloc == NULL || set_memory_ro == NULL || set_memory_x == NULL) {
        return false;
    }

    return true;
}

bool setup_payload(void)
{
    if (payload_len <= 0) {
        PRINTK("No payload defined\n");
        return false;
    }
    PRINTK("Loading payload\n");

    if (!resolve_required()) {
        PRINTK("Can't get Symbols needed.\n");
        return false;
    }

    return setup_elf(payload, payload_len);
}

void run_payload(void)
{
    if (start == NULL) return;
    PRINTK("Running payload\n");
    start();
}

int via_initcall_handler(void)
{
    int res = 0;
    PRINTK("Called via initcall\n");
    LOOKUP(regulator_init_complete);
    res = regulator_init_complete();

    if (setup_payload()) {
        run_payload();
    }
    return res;
}

/* the UEFI runtime hook runs in an interupt context, which makes several things
 * more complex. */
int via_uefi_runtime(void)
{
    void *ew;
    unsigned long flags;
    PRINTK("Called via UEFI Runtime hook\n");
    if (!setup_payload()) return 0;
    LOOKUP(execute_in_process_context);
    LOOKUP(irq_enter_rcu);
    LOOKUP(irq_exit_rcu);

    if (execute_in_process_context == NULL || irq_enter_rcu == NULL || \
            irq_exit_rcu == NULL) {
        PRINTK("missing symbols\n");
        return 0;
    }
    // we are leaking this.
    ew = kmalloc(1024, GFP_ATOMIC);
    /* Making it clear we are in an interrupt, as we want
     * execute_in_process_context to not run right now.
     * We have to save the irq flags, else we hit a warning about a firmware bug
     * so we also save that before restoring.
     *
     * We have to call a function like irq_enter_rcu() as that is the easiest
     * way of getting preempt_count() to be higher without us having to figure
     * out its offset (its a percpu value, changing between kernel versions), so
     * this just happens to be a bit more reliable. */
    /* from native_save_fl() in the kernel. */
    asm ("pushf; pop %0" : "=rm" (flags) : : "memory");
    irq_enter_rcu();
    execute_in_process_context(start, ew);
    irq_exit_rcu();
    asm ("mov %0, %%rax; push %%rax; popf" : : "rm" (flags) : "rax" );
    return 0;
}

/* Takes just the address of the _text section */
__attribute__ ((section(".text.start")))
int _kshelf_loader(unsigned long text, int via_initcall)
{
    LOOKUP_RAW(kallsyms_lookup_name_, (text + (void *)kallsyms_lookup_name_));
    LOOKUP(_printk);
    PRINTK("PATCHED KERNEL\n");
    PRINTK("payload_len: %i\n", payload_len);

    if (via_initcall) {
        return via_initcall_handler();
    }

    return via_uefi_runtime();
}
