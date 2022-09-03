#ifndef __WIDEVINE_H__
#define __WIDEVINE_H__

#include "types.h"
#include "QSEEComAPI.h"

// Setup everything needed for widevine to be able to encrypt and decrypt data
int widevine_setup(void);

// For both encrypt and decrypt, addresses can be overwritten by fd_info if it
// points to one of the following offsets:
#define WIDEVINE_CMD_IN_OFFSET (0x8)
#define WIDEVINE_CMD_OUT_OFFSET (0x28)
// Each operation (encrypt or decrypt) must be aligned to the size of an AES
// block
#define WIDEVINE_LEN_ALIGN (0x10)

int widevine_send_encrypt(physaddr_t in_addr, physaddr_t out_addr,
                          uint32_t len, struct QSEECom_ion_fd_info *fd_info);

int widevine_send_decrypt(physaddr_t in_addr, physaddr_t out_addr,
                          uint32_t len, struct QSEECom_ion_fd_info *fd_info);

// Get the QSEECom handle to the widevine app
struct QSEECom_handle *widevine_get_handle(void);

#endif // __WIDEVINE_H__

