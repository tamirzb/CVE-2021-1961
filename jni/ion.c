#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "linux_uapi/ion.h"
#include "linux_uapi/msm_ion.h"
#include "ion.h"

int ion_memalloc(size_t size, int heap_id, ion_data_t *ion_data)
{
    struct ion_allocation_data alloc_data = { .align = 0x1000, .len = size,
        .heap_id_mask = ION_HEAP(heap_id), .flags = 0, .handle = 0 };
    struct ion_fd_data fd_data = {0};

    ion_data->dev_fd = -1;
    ion_data->handle = 0;
    ion_data->fd = -1;
    ion_data->map = MAP_FAILED;
    ion_data->size = size;

    ion_data->dev_fd = open("/dev/ion", O_RDONLY);
    if (-1 == ion_data->dev_fd) {
        perror("[-] Failed to open /dev/ion");
        return 0;
    }

    if (0 != ioctl(ion_data->dev_fd, ION_IOC_ALLOC, &alloc_data)) {
        perror("[-] Failed to allocate ION buffer");
        goto err;
    }
    ion_data->handle = alloc_data.handle;

    fd_data.handle = alloc_data.handle;
    if (0 != ioctl(ion_data->dev_fd, ION_IOC_MAP, &fd_data)) {
        perror("[-] Failed to create ION map");
        goto err;
    }
    ion_data->fd = fd_data.fd;

    ion_data->map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
                         ion_data->fd, 0);
    if (MAP_FAILED == ion_data->map) {
        perror("[-] Failed to mmap ION buffer");
        goto err;
    }

    return 1;

err:
    ion_memfree(ion_data);
    return 0;
}

void ion_memfree(ion_data_t *ion_data)
{
    struct ion_handle_data handle_data = { .handle = ion_data->handle };

    if (MAP_FAILED != ion_data->map) {
        munmap(ion_data->map, ion_data->size);
        ion_data->map = MAP_FAILED;
    }

    if (-1 != ion_data->fd) {
        close(ion_data->fd);
        ion_data->fd = -1;
    }

    if (0 != ion_data->handle) {
        ioctl(ion_data->dev_fd, ION_IOC_FREE, &handle_data);
        ion_data->handle = 0;
    }

    if (-1 != ion_data->dev_fd) {
        close(ion_data->dev_fd);
        ion_data->dev_fd = -1;
    }
}
