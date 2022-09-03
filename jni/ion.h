#ifndef __ION_H__
#define __ION_H__

#include "linux_uapi/ion.h"

typedef struct {
    int dev_fd;
    ion_user_handle_t handle;
    int fd;
    void *map;
    size_t size;
} ion_data_t;

// Allocate and map an ION mapping
// Should be freed using ion_memfree
int ion_memalloc(size_t size, int heap_id, ion_data_t *ion_data);

void ion_memfree(ion_data_t *ion_data);

#endif // __ION_H__
