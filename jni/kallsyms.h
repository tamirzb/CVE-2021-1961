#ifndef __KALLSYMS_H__
#define __KALLSYMS_H__

#include <stdint.h>

#include "types.h"

int kallsyms_find(void);

// Returns the virtual address of `name`, or 0 if not found
uint64_t kallsyms_lookup_name(const char *name);

#endif // __KALLSYMS_H__
