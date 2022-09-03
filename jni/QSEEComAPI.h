#ifndef __QSEECOMAPI_H__
#define __QSEECOMAPI_H__

#include <stdint.h>

struct QSEECom_handle;

struct QSEECom_ion_fd_data {
    int32_t fd;
    uint32_t cmd_buf_offset;
};

struct QSEECom_ion_fd_info {
    struct QSEECom_ion_fd_data data[4];
};

int QSEECom_start_app(struct QSEECom_handle **clnt_handle, const char *path,
                      const char *fname, uint32_t sb_size);

int QSEECom_shutdown_app(struct QSEECom_handle **handle);

int QSEECom_send_cmd(struct QSEECom_handle *handle, void *send_buf,
                     uint32_t sbuf_len, void *rcv_buf, uint32_t rbuf_len);

int QSEECom_send_modified_cmd(struct QSEECom_handle *handle, void *send_buf,
                              uint32_t sbuf_len, void *resp_buf,
                              uint32_t rbuf_len,
                              struct QSEECom_ion_fd_info  *ifd_data);

int QSEECom_send_modified_cmd_64(struct QSEECom_handle *handle, void *send_buf,
                                 uint32_t sbuf_len, void *resp_buf,
                                 uint32_t rbuf_len,
                                 struct QSEECom_ion_fd_info *ifd_data);

#endif // __QSEECOMAPI_H__
