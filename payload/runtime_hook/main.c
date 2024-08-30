/* Our runtime hook */

typedef int (*_printk_t)(const char *fmt, ...);
_printk_t printk;

/* Takes just the address of the _text section */
__attribute__ ((section(".text.start")))
void _start(void *text)
{
    printk = (text + PRINTK_OFFSET);
    printk(">>> gr33tz\n");
    //while (1) {}
}
