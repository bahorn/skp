#include "main.h"

int regulator_init_complete(void);

// seperate function just to make this easier.
__attribute__ (( section (".text.start")))
void entry(void)
{
    // initcall we hooked
    regulator_init_complete();
    main();
}
