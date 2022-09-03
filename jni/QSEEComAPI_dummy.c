// This is a dummy of the libQSEEComAPI functions used in the exploit. This is
// needed so eventually the exploit binary will be dynamically linked with the
// real libQSEEComAPI.

#include "QSEEComAPI.h"

int QSEECom_start_app(struct QSEECom_handle **clnt_handle, const char *path,
                      const char *fname, uint32_t sb_size)
{
    return 0;
}

int QSEECom_shutdown_app(struct QSEECom_handle **handle)
{
    return 0;
}

int QSEECom_send_cmd(struct QSEECom_handle *handle, void *send_buf,
                     uint32_t sbuf_len, void *rcv_buf, uint32_t rbuf_len)
{
    return 0;
}

int QSEECom_send_modified_cmd(struct QSEECom_handle *handle, void *send_buf,
                              uint32_t sbuf_len, void *resp_buf,
                              uint32_t rbuf_len,
                              struct QSEECom_ion_fd_info  *ifd_data)
{
    return 0;
}

int QSEECom_send_modified_cmd_64(struct QSEECom_handle *handle, void *send_buf,
                                 uint32_t sbuf_len, void *resp_buf,
                                 uint32_t rbuf_len,
                                 struct QSEECom_ion_fd_info *ifd_data)
{
    return 0;
}
