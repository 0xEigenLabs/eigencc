#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_quote.h"
#include "time.h"
#include "inc/stat.h"
#include "sys/uio.h"
#include "inc/stat.h"
#include "inc/dirent.h"
#include "sys/socket.h"
#include "netdb.h"
#include "sys/socket.h"
#include "sys/epoll.h"
#include "poll.h"
#include "pwd.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

uint32_t ecall_ipc_entry_point(uint32_t cmd, const uint8_t* in_buf, size_t in_len, uint8_t* out_buf, size_t out_maxlen, size_t* real_out_len);
void t_global_init_ecall(uint64_t id, const uint8_t* path, size_t len);
void t_global_exit_ecall(void);

sgx_status_t SGX_CDECL ocall_sgx_init_quote(sgx_status_t* retval, sgx_target_info_t* p_target_info, sgx_epid_group_id_t* p_gid);
sgx_status_t SGX_CDECL ocall_sgx_get_ias_socket(int* retval);
sgx_status_t SGX_CDECL ocall_sgx_calc_quote_size(sgx_status_t* retval, uint8_t* p_sig_rl, uint32_t sig_rl_size, uint32_t* p_quote_size);
sgx_status_t SGX_CDECL ocall_sgx_get_quote(sgx_status_t* retval, sgx_report_t* p_report, sgx_quote_sign_type_t quote_type, sgx_spid_t* p_spid, sgx_quote_nonce_t* p_nonce, uint8_t* p_sig_rl, uint32_t sig_rl_size, sgx_report_t* p_qe_report, sgx_quote_t* p_quote, uint32_t quote_size);
sgx_status_t SGX_CDECL u_thread_set_event_ocall(int* retval, int* error, const void* tcs);
sgx_status_t SGX_CDECL u_thread_wait_event_ocall(int* retval, int* error, const void* tcs, const struct timespec* timeout);
sgx_status_t SGX_CDECL u_thread_set_multiple_events_ocall(int* retval, int* error, const void** tcss, int total);
sgx_status_t SGX_CDECL u_thread_setwait_events_ocall(int* retval, int* error, const void* waiter_tcs, const void* self_tcs, const struct timespec* timeout);
sgx_status_t SGX_CDECL u_clock_gettime_ocall(int* retval, int* error, int clk_id, struct timespec* tp);
sgx_status_t SGX_CDECL u_read_ocall(size_t* retval, int* error, int fd, void* buf, size_t count);
sgx_status_t SGX_CDECL u_pread64_ocall(size_t* retval, int* error, int fd, void* buf, size_t count, int64_t offset);
sgx_status_t SGX_CDECL u_readv_ocall(size_t* retval, int* error, int fd, const struct iovec* iov, int iovcnt);
sgx_status_t SGX_CDECL u_preadv64_ocall(size_t* retval, int* error, int fd, const struct iovec* iov, int iovcnt, int64_t offset);
sgx_status_t SGX_CDECL u_write_ocall(size_t* retval, int* error, int fd, const void* buf, size_t count);
sgx_status_t SGX_CDECL u_pwrite64_ocall(size_t* retval, int* error, int fd, const void* buf, size_t count, int64_t offset);
sgx_status_t SGX_CDECL u_writev_ocall(size_t* retval, int* error, int fd, const struct iovec* iov, int iovcnt);
sgx_status_t SGX_CDECL u_pwritev64_ocall(size_t* retval, int* error, int fd, const struct iovec* iov, int iovcnt, int64_t offset);
sgx_status_t SGX_CDECL u_fcntl_arg0_ocall(int* retval, int* error, int fd, int cmd);
sgx_status_t SGX_CDECL u_fcntl_arg1_ocall(int* retval, int* error, int fd, int cmd, int arg);
sgx_status_t SGX_CDECL u_ioctl_arg0_ocall(int* retval, int* error, int fd, int request);
sgx_status_t SGX_CDECL u_ioctl_arg1_ocall(int* retval, int* error, int fd, int request, int* arg);
sgx_status_t SGX_CDECL u_close_ocall(int* retval, int* error, int fd);
sgx_status_t SGX_CDECL u_malloc_ocall(void** retval, int* error, size_t size);
sgx_status_t SGX_CDECL u_free_ocall(void* p);
sgx_status_t SGX_CDECL u_mmap_ocall(void** retval, int* error, void* start, size_t length, int prot, int flags, int fd, int64_t offset);
sgx_status_t SGX_CDECL u_munmap_ocall(int* retval, int* error, void* start, size_t length);
sgx_status_t SGX_CDECL u_msync_ocall(int* retval, int* error, void* addr, size_t length, int flags);
sgx_status_t SGX_CDECL u_mprotect_ocall(int* retval, int* error, void* addr, size_t length, int prot);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL u_open_ocall(int* retval, int* error, const char* pathname, int flags);
sgx_status_t SGX_CDECL u_open64_ocall(int* retval, int* error, const char* path, int oflag, int mode);
sgx_status_t SGX_CDECL u_fstat_ocall(int* retval, int* error, int fd, struct stat_t* buf);
sgx_status_t SGX_CDECL u_fstat64_ocall(int* retval, int* error, int fd, struct stat64_t* buf);
sgx_status_t SGX_CDECL u_stat_ocall(int* retval, int* error, const char* path, struct stat_t* buf);
sgx_status_t SGX_CDECL u_stat64_ocall(int* retval, int* error, const char* path, struct stat64_t* buf);
sgx_status_t SGX_CDECL u_lstat_ocall(int* retval, int* error, const char* path, struct stat_t* buf);
sgx_status_t SGX_CDECL u_lstat64_ocall(int* retval, int* error, const char* path, struct stat64_t* buf);
sgx_status_t SGX_CDECL u_lseek_ocall(uint64_t* retval, int* error, int fd, int64_t offset, int whence);
sgx_status_t SGX_CDECL u_lseek64_ocall(int64_t* retval, int* error, int fd, int64_t offset, int whence);
sgx_status_t SGX_CDECL u_ftruncate_ocall(int* retval, int* error, int fd, int64_t length);
sgx_status_t SGX_CDECL u_ftruncate64_ocall(int* retval, int* error, int fd, int64_t length);
sgx_status_t SGX_CDECL u_truncate_ocall(int* retval, int* error, const char* path, int64_t length);
sgx_status_t SGX_CDECL u_truncate64_ocall(int* retval, int* error, const char* path, int64_t length);
sgx_status_t SGX_CDECL u_fsync_ocall(int* retval, int* error, int fd);
sgx_status_t SGX_CDECL u_fdatasync_ocall(int* retval, int* error, int fd);
sgx_status_t SGX_CDECL u_fchmod_ocall(int* retval, int* error, int fd, uint32_t mode);
sgx_status_t SGX_CDECL u_unlink_ocall(int* retval, int* error, const char* pathname);
sgx_status_t SGX_CDECL u_link_ocall(int* retval, int* error, const char* oldpath, const char* newpath);
sgx_status_t SGX_CDECL u_rename_ocall(int* retval, int* error, const char* oldpath, const char* newpath);
sgx_status_t SGX_CDECL u_chmod_ocall(int* retval, int* error, const char* path, uint32_t mode);
sgx_status_t SGX_CDECL u_readlink_ocall(size_t* retval, int* error, const char* path, char* buf, size_t bufsz);
sgx_status_t SGX_CDECL u_symlink_ocall(int* retval, int* error, const char* path1, const char* path2);
sgx_status_t SGX_CDECL u_realpath_ocall(char** retval, int* error, const char* pathname);
sgx_status_t SGX_CDECL u_mkdir_ocall(int* retval, int* error, const char* pathname, uint32_t mode);
sgx_status_t SGX_CDECL u_rmdir_ocall(int* retval, int* error, const char* pathname);
sgx_status_t SGX_CDECL u_opendir_ocall(void** retval, int* error, const char* pathname);
sgx_status_t SGX_CDECL u_readdir64_r_ocall(int* retval, void* dirp, struct dirent64_t* entry, struct dirent64_t** result);
sgx_status_t SGX_CDECL u_closedir_ocall(int* retval, int* error, void* dirp);
sgx_status_t SGX_CDECL u_dirfd_ocall(int* retval, int* error, void* dirp);
sgx_status_t SGX_CDECL u_fstatat64_ocall(int* retval, int* error, int dirfd, const char* pathname, struct stat64_t* buf, int flags);
sgx_status_t SGX_CDECL u_getaddrinfo_ocall(int* retval, int* error, const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res);
sgx_status_t SGX_CDECL u_freeaddrinfo_ocall(struct addrinfo* res);
sgx_status_t SGX_CDECL u_gai_strerror_ocall(char** retval, int errcode);
sgx_status_t SGX_CDECL u_socket_ocall(int* retval, int* error, int domain, int ty, int protocol);
sgx_status_t SGX_CDECL u_socketpair_ocall(int* retval, int* error, int domain, int ty, int protocol, int sv[2]);
sgx_status_t SGX_CDECL u_bind_ocall(int* retval, int* error, int sockfd, const struct sockaddr* addr, socklen_t addrlen);
sgx_status_t SGX_CDECL u_listen_ocall(int* retval, int* error, int sockfd, int backlog);
sgx_status_t SGX_CDECL u_accept_ocall(int* retval, int* error, int sockfd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out);
sgx_status_t SGX_CDECL u_accept4_ocall(int* retval, int* error, int sockfd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out, int flags);
sgx_status_t SGX_CDECL u_connect_ocall(int* retval, int* error, int sockfd, const struct sockaddr* addr, socklen_t addrlen);
sgx_status_t SGX_CDECL u_recv_ocall(size_t* retval, int* error, int sockfd, void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL u_recvfrom_ocall(size_t* retval, int* error, int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t addrlen_in, socklen_t* addrlen_out);
sgx_status_t SGX_CDECL u_recvmsg_ocall(size_t* retval, int* error, int sockfd, struct msghdr* msg, int flags);
sgx_status_t SGX_CDECL u_send_ocall(size_t* retval, int* error, int sockfd, const void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL u_sendto_ocall(size_t* retval, int* error, int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen);
sgx_status_t SGX_CDECL u_sendmsg_ocall(size_t* retval, int* error, int sockfd, const struct msghdr* msg, int flags);
sgx_status_t SGX_CDECL u_getsockopt_ocall(int* retval, int* error, int sockfd, int level, int optname, void* optval, socklen_t optlen_in, socklen_t* optlen_out);
sgx_status_t SGX_CDECL u_setsockopt_ocall(int* retval, int* error, int sockfd, int level, int optname, const void* optval, socklen_t optlen);
sgx_status_t SGX_CDECL u_getsockname_ocall(int* retval, int* error, int sockfd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out);
sgx_status_t SGX_CDECL u_getpeername_ocall(int* retval, int* error, int sockfd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out);
sgx_status_t SGX_CDECL u_shutdown_ocall(int* retval, int* error, int sockfd, int how);
sgx_status_t SGX_CDECL u_poll_ocall(int* retval, int* error, struct pollfd* fds, nfds_t nfds, int timeout);
sgx_status_t SGX_CDECL u_epoll_create1_ocall(int* retval, int* error, int flags);
sgx_status_t SGX_CDECL u_epoll_ctl_ocall(int* retval, int* error, int epfd, int op, int fd, struct epoll_event* event);
sgx_status_t SGX_CDECL u_epoll_wait_ocall(int* retval, int* error, int epfd, struct epoll_event* events, int maxevents, int timeout);
sgx_status_t SGX_CDECL u_environ_ocall(char*** retval);
sgx_status_t SGX_CDECL u_getenv_ocall(char** retval, const char* name);
sgx_status_t SGX_CDECL u_setenv_ocall(int* retval, int* error, const char* name, const char* value, int overwrite);
sgx_status_t SGX_CDECL u_unsetenv_ocall(int* retval, int* error, const char* name);
sgx_status_t SGX_CDECL u_chdir_ocall(int* retval, int* error, const char* dir);
sgx_status_t SGX_CDECL u_getcwd_ocall(char** retval, int* error, char* buf, size_t buflen);
sgx_status_t SGX_CDECL u_getpwuid_r_ocall(int* retval, unsigned int uid, struct passwd* pwd, char* buf, size_t buflen, struct passwd** passwd_result);
sgx_status_t SGX_CDECL u_getuid_ocall(unsigned int* retval);
sgx_status_t SGX_CDECL u_sgxprotectedfs_exclusive_file_open(void** retval, const char* filename, uint8_t read_only, int64_t* file_size, int32_t* error_code);
sgx_status_t SGX_CDECL u_sgxprotectedfs_check_if_file_exists(uint8_t* retval, const char* filename);
sgx_status_t SGX_CDECL u_sgxprotectedfs_fread_node(int32_t* retval, void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size);
sgx_status_t SGX_CDECL u_sgxprotectedfs_fwrite_node(int32_t* retval, void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size);
sgx_status_t SGX_CDECL u_sgxprotectedfs_fclose(int32_t* retval, void* f);
sgx_status_t SGX_CDECL u_sgxprotectedfs_fflush(uint8_t* retval, void* f);
sgx_status_t SGX_CDECL u_sgxprotectedfs_remove(int32_t* retval, const char* filename);
sgx_status_t SGX_CDECL u_sgxprotectedfs_recovery_file_open(void** retval, const char* filename);
sgx_status_t SGX_CDECL u_sgxprotectedfs_fwrite_recovery_node(uint8_t* retval, void* f, uint8_t* data, uint32_t data_length);
sgx_status_t SGX_CDECL u_sgxprotectedfs_do_file_recovery(int32_t* retval, const char* filename, const char* recovery_filename, uint32_t node_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
