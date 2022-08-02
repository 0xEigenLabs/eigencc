// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

use sgx_types::*;
use super::*;
use alloc::slice;
use alloc::vec::Vec;
use alloc::boxed::Box;
use core::ptr;
use core::mem;

const MAX_OCALL_ALLOC_SIZE: size_t = 0x4000; //16K
extern "C" {
    // memory
    pub fn u_malloc_ocall(result: *mut *mut c_void, error: *mut c_int, size: size_t) -> sgx_status_t;
    pub fn u_free_ocall(p: *mut c_void) -> sgx_status_t;
    pub fn u_mmap_ocall(result: *mut *mut c_void,
                        error: *mut c_int,
                        start: *mut c_void,
                        length: size_t,
                        prot: c_int,
                        flags: c_int,
                        fd: c_int,
                        offset: off_t) -> sgx_status_t;
    pub fn u_munmap_ocall(result: *mut c_int,
                          error: *mut c_int,
                          start: *mut c_void,
                          length: size_t) -> sgx_status_t;
    pub fn u_msync_ocall(result: *mut c_int,
                         error: *mut c_int,
                         addr: *mut c_void,
                         length: size_t,
                         flags: c_int) -> sgx_status_t;

    pub fn u_mprotect_ocall(result: *mut c_int,
                            error: *mut c_int,
                            addr: *mut c_void,
                            length: size_t,
                            prot: c_int) -> sgx_status_t;
    // env
    pub fn u_getuid_ocall(result: *mut uid_t) -> sgx_status_t;
    pub fn u_environ_ocall(result: *mut *const *const c_char) -> sgx_status_t;
    pub fn u_getenv_ocall(result: *mut *const c_char,
                          name: *const c_char) -> sgx_status_t;
    pub fn u_setenv_ocall(result: *mut c_int,
                          error: *mut c_int,
                          name: *const c_char,
                          value: *const c_char,
                          overwrite: c_int) -> sgx_status_t;
    pub fn u_unsetenv_ocall(result: *mut c_int,
                            error: *mut c_int,
                            name: *const c_char) -> sgx_status_t;
    pub fn u_getcwd_ocall(result: *mut *mut c_char,
                          error: *mut c_int,
                          buf: *mut c_char,
                          size: size_t) -> sgx_status_t;
    pub fn u_chdir_ocall(result: *mut c_int,  error: *mut c_int, dir: *const c_char) -> sgx_status_t;
    pub fn u_getpwuid_r_ocall(result: *mut c_int,
                              uid: uid_t,
                              pwd: *mut passwd,
                              buf: *mut c_char,
                              buflen: size_t,
                              passwd_result: *mut *mut passwd) -> sgx_status_t;
    // file
    pub fn u_open_ocall(result: *mut c_int,
                        error: *mut c_int,
                        path: *const c_char,
                        flags: c_int) -> sgx_status_t;
    pub fn u_open64_ocall(result: *mut c_int,
                          error: *mut c_int,
                          path: *const c_char,
                          oflag: c_int,
                          mode: c_int) -> sgx_status_t;
    pub fn u_fstat_ocall(result: *mut c_int,
                         error: *mut c_int,
                         fd: c_int,
                         buf: *mut stat) -> sgx_status_t;
    pub fn u_fstat64_ocall(result: *mut c_int,
                           error: *mut c_int,
                           fd: c_int,
                           buf: *mut stat64) -> sgx_status_t;
    pub fn u_stat_ocall(result: *mut c_int,
                        error: *mut c_int,
                        path: *const c_char,
                        buf: *mut stat) -> sgx_status_t;
    pub fn u_stat64_ocall(result: *mut c_int,
                          error: *mut c_int,
                          path: *const c_char,
                          buf: *mut stat64) -> sgx_status_t;
    pub fn u_lstat_ocall(result: *mut c_int,
                         error: *mut c_int,
                         path: *const c_char,
                         buf: *mut stat) -> sgx_status_t;
    pub fn u_lstat64_ocall(result: *mut c_int,
                           error: *mut c_int,
                           path: *const c_char,
                           buf: *mut stat64) -> sgx_status_t;
    pub fn u_lseek_ocall(result: *mut off_t,
                         error: *mut c_int,
                         fd: c_int,
                         offset: off_t,
                         whence: c_int) -> sgx_status_t;
    pub fn u_lseek64_ocall(result: *mut off64_t,
                           error: *mut c_int,
                           fd: c_int,
                           offset: off64_t,
                           whence: c_int) -> sgx_status_t;
    pub fn u_ftruncate_ocall(result: *mut c_int,
                             error: *mut c_int,
                             fd: c_int,
                             length: off_t) -> sgx_status_t;
    pub fn u_ftruncate64_ocall(result: *mut c_int,
                               error: *mut c_int,
                               fd: c_int,
                               length: off64_t) -> sgx_status_t;
    pub fn u_truncate_ocall(result: *mut c_int,
                            error: *mut c_int,
                            path: *const c_char,
                            length: off_t) -> sgx_status_t;
    pub fn u_truncate64_ocall(result: *mut c_int,
                              error: *mut c_int,
                              path: *const c_char,
                              length: off64_t) -> sgx_status_t;
    pub fn u_fsync_ocall(result: *mut c_int,
                         error: *mut c_int,
                         fd: c_int) -> sgx_status_t;
    pub fn u_fdatasync_ocall(result: *mut c_int,
                             error: *mut c_int,
                             fd: c_int) -> sgx_status_t;
    pub fn u_fchmod_ocall(result: *mut c_int,
                          error: *mut c_int,
                          fd: c_int,
                          mode: mode_t) -> sgx_status_t;
    pub fn u_unlink_ocall(result: *mut c_int,
                          error: *mut c_int,
                          pathname: *const c_char) -> sgx_status_t;
    pub fn u_link_ocall(result: *mut c_int,
                        error: *mut c_int,
                        oldpath: *const c_char,
                        newpath: *const c_char) -> sgx_status_t;
    pub fn u_rename_ocall(result: *mut c_int,
                          error: *mut c_int,
                          oldpath: *const c_char,
                          newpath: *const c_char) -> sgx_status_t;
    pub fn u_chmod_ocall(result: *mut c_int,
                         error: *mut c_int,
                         path: *const c_char,
                         mode: mode_t) -> sgx_status_t;
    pub fn u_readlink_ocall(result: *mut ssize_t,
                            error: *mut c_int,
                            path: *const c_char,
                            buf: *mut c_char,
                            bufsz: size_t) -> sgx_status_t;
    pub fn u_symlink_ocall(result: *mut c_int,
                           error: *mut c_int,
                           path1: *const c_char,
                           path2: *const c_char) -> sgx_status_t;
    pub fn u_realpath_ocall(result: *mut *mut c_char,
                            error: *mut c_int,
                            pathname: *const c_char) -> sgx_status_t;
    pub fn u_mkdir_ocall(result: *mut c_int,
                         error: *mut c_int,
                         pathname: *const c_char,
                         mode: mode_t) -> sgx_status_t;
    pub fn u_rmdir_ocall(result: *mut c_int,
                         error: *mut c_int,
                         pathname: *const c_char) -> sgx_status_t;
    pub fn u_opendir_ocall(result: *mut *mut DIR,
                           error: *mut c_int,
                           pathname: *const c_char) -> sgx_status_t;
    pub fn u_readdir64_r_ocall(result: *mut c_int,
                               dirp: *mut DIR,
                               entry: *mut dirent64,
                               dirresult: *mut *mut  dirent64) -> sgx_status_t;
    pub fn u_closedir_ocall(result: *mut c_int,
                            error: *mut c_int,
                            dirp: *mut DIR) -> sgx_status_t;
    pub fn u_dirfd_ocall(result: *mut c_int,
                         error: *mut c_int,
                         dirp: *mut DIR) -> sgx_status_t;
    pub fn u_fstatat64_ocall(result: *mut c_int,
                             error: *mut c_int,
                             dirfd: c_int,
                             pathname: *const c_char,
                             buf: *mut stat64,
                             flags: c_int) -> sgx_status_t;
    // fd
    pub fn u_read_ocall(result: *mut ssize_t,
                        errno: *mut c_int,
                        fd: c_int,
                        buf: *mut c_void,
                        count: size_t) -> sgx_status_t;
    pub fn u_pread64_ocall(result: *mut ssize_t,
                           errno: *mut c_int,
                           fd: c_int,
                           buf: *mut c_void,
                           count: size_t,
                           offset: off64_t) -> sgx_status_t;
    pub fn u_readv_ocall(result: *mut ssize_t,
                         errno: *mut c_int,
                         fd: c_int,
                         iov: *const iovec,
                         iovcnt: c_int) -> sgx_status_t;
    pub fn u_preadv64_ocall(result: *mut ssize_t,
                            errno: *mut c_int,
                            fd: c_int,
                            iov: *const iovec,
                            iovcnt: c_int,
                            offset: off64_t) -> sgx_status_t;
    pub fn u_write_ocall(result: *mut ssize_t,
                         errno: *mut c_int,
                         fd: c_int,
                         buf: *const c_void,
                         count: size_t) -> sgx_status_t;
    pub fn u_pwrite64_ocall(result: *mut ssize_t,
                            errno: *mut c_int,
                            fd: c_int,
                            buf: *const c_void,
                            count: size_t,
                            offset: off64_t) -> sgx_status_t;
    pub fn u_writev_ocall(result: *mut ssize_t,
                          errno: *mut c_int,
                          fd: c_int,
                          iov: *const iovec,
                          iovcnt: c_int) -> sgx_status_t;
    pub fn u_pwritev64_ocall(result: *mut ssize_t,
                             errno: *mut c_int,
                             fd: c_int,
                             iov: *const iovec,
                             iovcnt: c_int,
                             offset: off64_t) -> sgx_status_t;
    pub fn u_fcntl_arg0_ocall(result: *mut c_int,
                              errno: *mut c_int,
                              fd: c_int,
                              cmd: c_int) -> sgx_status_t;
    pub fn u_fcntl_arg1_ocall(result: *mut c_int,
                              errno: *mut c_int,
                              fd: c_int,
                              cmd: c_int,
                              arg: c_int) -> sgx_status_t;
    pub fn u_ioctl_arg0_ocall(result: *mut c_int,
                              errno: *mut c_int,
                              fd: c_int,
                              request: c_int) -> sgx_status_t;
    pub fn u_ioctl_arg1_ocall(result: *mut c_int,
                              errno: *mut c_int,
                              fd: c_int,
                              request: c_int,
                              arg: *mut c_int) -> sgx_status_t;
    pub fn u_close_ocall(result: *mut c_int,
                         errno: *mut c_int,
                         fd: c_int) -> sgx_status_t;
    // time
    pub fn u_clock_gettime_ocall(result: *mut c_int,
                                 errno: *mut c_int,
                                 clk_id: clockid_t,
                                 tp: *mut timespec) -> sgx_status_t;
    // socket
    pub fn u_socket_ocall(result: *mut c_int,
                          errno: *mut c_int,
                          domain: c_int,
                          ty: c_int,
                          protocol: c_int) -> sgx_status_t;
    pub fn u_socketpair_ocall(result: *mut c_int,
                              errno: *mut c_int,
                              domain: c_int,
                              ty: c_int,
                              protocol: c_int,
                              sv: *mut c_int) -> sgx_status_t;
    pub fn u_bind_ocall(result: *mut c_int,
                        errno: *mut c_int,
                        sockfd: c_int,
                        address: *const sockaddr,
                        addrlen: socklen_t) -> sgx_status_t;
    pub fn u_listen_ocall(result: *mut c_int,
                          error: *mut c_int,
                          sockfd: c_int,
                          backlog: c_int) -> sgx_status_t;
    pub fn u_accept_ocall(result: *mut c_int,
                          errno: *mut c_int,
                          sockfd: c_int,
                          addr: *mut sockaddr,
                          addrlen_in: socklen_t,
                          addrlen_out: *mut socklen_t) -> sgx_status_t;
    pub fn u_accept4_ocall(result: *mut c_int,
                           errno: *mut c_int,
                           sockfd: c_int,
                           addr: *mut sockaddr,
                           addrlen_in: socklen_t,
                           addrlen_out: *mut socklen_t,
                           flags: c_int) -> sgx_status_t;
    pub fn u_connect_ocall(result: *mut c_int,
                           errno: *mut c_int,
                           sockfd: c_int,
                           address: *const sockaddr,
                           addrlen: socklen_t) -> sgx_status_t;
    pub fn u_send_ocall(result: *mut ssize_t,
                        errno: *mut c_int,
                        sockfd: c_int,
                        buf: *const c_void,
                        len: size_t,
                        flags: c_int) -> sgx_status_t;
    pub fn u_sendto_ocall(result: *mut ssize_t,
                          errno: *mut c_int,
                          sockfd: c_int,
                          buf: *const c_void,
                          len: size_t,
                          flags: c_int,
                          addr: *const sockaddr,
                          addrlen: socklen_t) -> sgx_status_t;
    pub fn u_sendmsg_ocall(result: *mut ssize_t,
                           error: *mut c_int,
                           sockfd: c_int,
                           msg: *const msghdr,
                           flags: c_int) -> sgx_status_t;
    pub fn u_recv_ocall(result: *mut ssize_t,
                        errno: *mut c_int,
                        sockfd: c_int,
                        buf: *mut c_void,
                        len: size_t,
                        flags: c_int) -> sgx_status_t;
    pub fn u_recvfrom_ocall(result: *mut ssize_t,
                            errno: *mut c_int,
                            sockfd: c_int,
                            buf: *mut c_void,
                            len: size_t,
                            flags: c_int,
                            addr: *mut sockaddr,
                            addrlen_in: socklen_t,
                            addrlen_out: *mut socklen_t) -> sgx_status_t;
    pub fn u_recvmsg_ocall(result: *mut ssize_t,
                           error: *mut c_int,
                           sockfd: c_int,
                           msg: *mut msghdr,
                           flags: c_int) -> sgx_status_t;
    pub fn u_setsockopt_ocall(result: *mut c_int,
                              errno: *mut c_int,
                              sockfd: c_int,
                              level: c_int,
                              optname: c_int,
                              optval: *const c_void,
                              optlen: socklen_t) -> sgx_status_t;
    pub fn u_getsockopt_ocall(result: *mut c_int,
                              errno: *mut c_int,
                              sockfd: c_int,
                              level: c_int,
                              optname: c_int,
                              optval: *mut c_void,
                              optlen_in: socklen_t,
                              optlen_out: *mut socklen_t) -> sgx_status_t;
    pub fn u_getpeername_ocall(result: *mut c_int,
                               errno: *mut c_int,
                               sockfd: c_int,
                               address: *mut sockaddr,
                               addrlen_in: socklen_t,
                               addrlen_out: *mut socklen_t) -> sgx_status_t;
    pub fn u_getsockname_ocall(result: *mut c_int,
                               errno: *mut c_int,
                               sockfd: c_int,
                               address: *mut sockaddr,
                               addrlen_in: socklen_t,
                               addrlen_out: *mut socklen_t) -> sgx_status_t;
    pub fn u_shutdown_ocall(result: *mut c_int,
                            errno: *mut c_int,
                            sockfd: c_int,
                            how: c_int) -> sgx_status_t;
    // net
    pub fn u_getaddrinfo_ocall(result: *mut c_int,
                               errno: *mut c_int,
                               node: *const c_char,
                               service: *const c_char,
                               hints: *const addrinfo,
                               res: *mut *mut addrinfo) -> sgx_status_t;
    pub fn u_freeaddrinfo_ocall(res: *mut addrinfo) -> sgx_status_t;
    pub fn u_gai_strerror_ocall(result: *mut *const c_char, errcode: c_int) -> sgx_status_t;
    // async io
    pub fn u_poll_ocall(result: *mut c_int,
                        errno: *mut c_int,
                        fds: *mut pollfd,
                        nfds: nfds_t,
                        timeout: c_int) -> sgx_status_t;
    pub fn u_epoll_create1_ocall(result: *mut c_int,
                                 error: *mut c_int,
                                 flags: c_int) -> sgx_status_t;
    pub fn u_epoll_ctl_ocall(result: *mut c_int,
                             error: *mut c_int,
                             epfd: c_int,
                             op: c_int,
                             fd: c_int,
                             event: *mut epoll_event) -> sgx_status_t;
    pub fn u_epoll_wait_ocall(result: *mut c_int,
                              error: *mut c_int,
                              epfd: c_int,
                              events: *mut epoll_event,
                              maxevents: c_int,
                              timeout: c_int) -> sgx_status_t;
    // sys
    pub fn u_sysconf_ocall(result: *mut c_long,
                           error: *mut c_int,
                           name: c_int) -> sgx_status_t;
    pub fn u_prctl_ocall(result: *mut c_int,
                         error: *mut c_int,
                         option: c_int,
                         arg2: c_ulong,
                         arg3: c_ulong,
                         arg4: c_ulong,
                         arg5: c_ulong) -> sgx_status_t;
    pub fn u_sched_setaffinity_ocall(result: *mut c_int,
                                     error: *mut c_int,
                                     pid: pid_t,
                                     cpusetsize: size_t,
                                     mask: *const cpu_set_t) -> sgx_status_t;
    pub fn u_sched_getaffinity_ocall(result: *mut c_int,
                                     error: *mut c_int,
                                     pid: pid_t,
                                     cpusetsize: size_t,
                                     mask: *mut cpu_set_t) -> sgx_status_t;
    // pipe
    pub fn u_pipe_ocall(result: *mut c_int,
                        error: *mut c_int,
                        fds: *mut c_int) -> sgx_status_t;
    pub fn u_pipe2_ocall(result: *mut c_int,
                         error: *mut c_int,
                         fds: *mut c_int,
                         flags: c_int) -> sgx_status_t;
    //thread
    pub  fn u_sched_yield_ocall(result: *mut c_int,
                                error: *mut c_int) -> sgx_status_t;
    pub  fn u_nanosleep_ocall(result: *mut c_int,
                              error: *mut c_int,
                              rqtp: *const timespec,
                              rmtp: *mut timespec) -> sgx_status_t;
    //signal
    pub fn u_sigaction_ocall(result: *mut c_int,
                             error: *mut c_int,
                             signum: c_int,
                             act: *const sigaction,
                             oldact: *mut sigaction,
                             enclave_id: uint64_t) -> sgx_status_t;
    pub fn u_sigprocmask_ocall(result: *mut c_int,
                                error: *mut c_int,
                                signum: c_int,
                                set: *const sigset_t,
                                oldset: *mut sigset_t) -> sgx_status_t;
    pub fn u_raise_ocall(result: *mut c_int, signum: c_int) -> sgx_status_t;
    //process
    pub fn u_getpid_ocall(result: *mut pid_t) -> sgx_status_t;
}

pub unsafe fn malloc(size: size_t) -> *mut c_void {
    let mut result: *mut c_void = ptr::null_mut();
    let mut error: c_int = 0;
    let status = u_malloc_ocall(&mut result as *mut *mut c_void,
                                &mut error as *mut c_int,
                                size);

    if status == sgx_status_t::SGX_SUCCESS {
        if result.is_null() {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = ptr::null_mut();
    }

    if sgx_is_outside_enclave(result, size) == 0 {
        set_errno(ESGX);
        result = ptr::null_mut();
    }

    result
}

pub unsafe fn free(p: *mut c_void) {
    let _ = u_free_ocall(p);
}

pub unsafe fn mmap(start: *mut c_void,
                   length: size_t,
                   prot: c_int,
                   flags: c_int,
                   fd: c_int,
                   offset: off_t) -> *mut c_void {
    let mut result: *mut c_void = ptr::null_mut();
    let mut error: c_int = 0;
    let status = u_mmap_ocall(&mut result as *mut *mut c_void,
                              &mut error as *mut c_int,
                              start,
                              length,
                              prot,
                              flags,
                              fd,
                              offset);

    if status == sgx_status_t::SGX_SUCCESS {
        if result as isize == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1 as isize as *mut c_void;
    }

    if sgx_is_outside_enclave(result, length) == 0 {
        set_errno(ESGX);
        result = -1 as isize as *mut c_void;
    }

    result
}

pub unsafe fn munmap(start: *mut c_void, length: size_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_munmap_ocall(&mut result as *mut c_int,
                                &mut error as *mut c_int,
                                start,
                                length);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn msync(addr: *mut c_void, length: size_t, flags: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_msync_ocall(&mut result as *mut c_int,
                               &mut error as *mut c_int,
                               addr,
                               length,
                               flags);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn mprotect(addr: *mut c_void, length: size_t, prot: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_mprotect_ocall(&mut result as *mut c_int,
                                  &mut error as *mut c_int,
                                  addr,
                                  length,
                                  prot);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn getuid() -> uid_t {
    let mut result: uid_t = 0;
    let status = u_getuid_ocall(&mut result as *mut uid_t);
    if status != sgx_status_t::SGX_SUCCESS {
         set_errno(ESGX);
         result = 0;
    }
    result
}

pub unsafe fn environ() -> *const *const c_char {
    let mut result: *const *const c_char = ptr::null();
    let status = u_environ_ocall(&mut result as *mut *const *const c_char);

    if status != sgx_status_t::SGX_SUCCESS {
        result = ptr::null();
    }
    result
}

pub unsafe fn getenv(name: *const c_char) -> *const c_char {
    let mut result: *const c_char = ptr::null();
    let status = u_getenv_ocall(&mut result as *mut *const c_char, name);

    if status != sgx_status_t::SGX_SUCCESS {
        result = ptr::null();
    }
    result
}

pub unsafe fn setenv(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_setenv_ocall(&mut result as *mut c_int,
                                &mut error as *mut c_int,
                                name,
                                value,
                                overwrite);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn unsetenv(name: *const c_char) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_unsetenv_ocall(&mut result as *mut c_int,
                                  &mut error as *mut c_int,
                                  name);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn getcwd(buf: *mut c_char, size: size_t) -> *mut c_char {
    let mut result: *mut c_char = ptr::null_mut();
    let mut error: c_int = 0;
    let status = u_getcwd_ocall(&mut result as *mut *mut c_char, &mut error as *mut c_int, buf, size);
    if status == sgx_status_t::SGX_SUCCESS {
        if result.is_null() {
            set_errno(error);
        } else {
            result = buf;
        }
    } else {
        set_errno(ESGX);
        result = ptr::null_mut();
    }
    result
}

pub unsafe fn chdir(dir: *const c_char) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_chdir_ocall(&mut result as *mut c_int, &mut error as *mut c_int, dir);
    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn getpwuid_r(uid: uid_t,
                         pwd: *mut passwd,
                         buf: *mut c_char,
                         buflen: size_t,
                         passwd_result:  *mut *mut passwd) -> c_int {
    let mut result: c_int = 0;
    let status = u_getpwuid_r_ocall(&mut result as *mut c_int,
                                    uid,
                                    pwd,
                                    buf,
                                    buflen,
                                    passwd_result);
    if status == sgx_status_t::SGX_SUCCESS && result == 0 {
        let pwd_ret = *passwd_result;
        if !pwd_ret.is_null() {
            let mut temp_pwd = &mut *pwd;
            let mut temp_buf = buf;
            if temp_pwd.pw_name as usize != -1_isize as usize {
                temp_pwd.pw_name = temp_buf.offset(temp_pwd.pw_name as isize);
            } else {
                temp_pwd.pw_name = ptr::null_mut();
            }
            temp_buf = buf;
            if temp_pwd.pw_passwd as usize != -1_isize as usize {
                temp_pwd.pw_passwd = temp_buf.offset(temp_pwd.pw_passwd as isize);
            } else {
                temp_pwd.pw_passwd = ptr::null_mut();
            }
            temp_buf = buf;
            if temp_pwd.pw_gecos as usize != -1_isize as usize {
                temp_pwd.pw_gecos = temp_buf.offset(temp_pwd.pw_gecos as isize);
            } else {
                temp_pwd.pw_gecos = ptr::null_mut();
            }
            temp_buf = buf;
            if temp_pwd.pw_dir as usize != -1_isize as usize {
                temp_pwd.pw_dir = temp_buf.offset(temp_pwd.pw_dir as isize);
            } else {
                temp_pwd.pw_dir = ptr::null_mut();
            }
            temp_buf = buf;
            if temp_pwd.pw_shell as usize != -1_isize as usize {
                temp_pwd.pw_shell = temp_buf.offset(temp_pwd.pw_shell as isize);
            } else {
                temp_pwd.pw_shell = ptr::null_mut();
            }
            *passwd_result = pwd;
        }
    } else {
        *passwd_result = ptr::null_mut();
        if status != sgx_status_t::SGX_SUCCESS {
            result = ESGX;
        }
    }
    result
}

pub unsafe fn open(path: *const c_char, flags: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_open_ocall(&mut result as *mut c_int,
                              &mut error as *mut c_int,
                              path,
                              flags);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn open64(path: *const c_char, oflag: c_int, mode: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_open64_ocall(&mut result as *mut c_int,
                                &mut error as *mut c_int,
                                path,
                                oflag,
                                mode);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn fstat(fd: c_int, buf: *mut stat) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_fstat_ocall(&mut result as *mut c_int,
                               &mut error as *mut c_int,
                               fd,
                               buf);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn fstat64(fd: c_int, buf: *mut stat64) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_fstat64_ocall(&mut result as *mut c_int,
                                 &mut error as *mut c_int,
                                 fd,
                                 buf);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn stat(path: *const c_char, buf: *mut stat) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_stat_ocall(&mut result as *mut c_int,
                              &mut error as *mut c_int,
                              path,
                              buf);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn stat64(path: *const c_char, buf: *mut stat64) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_stat64_ocall(&mut result as *mut c_int,
                                &mut error as *mut c_int,
                                path,
                                buf);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn lstat(path: *const c_char, buf: *mut stat) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_lstat_ocall(&mut result as *mut c_int,
                               &mut error as *mut c_int,
                               path,
                               buf);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn lstat64(path: *const c_char, buf: *mut stat64) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_lstat64_ocall(&mut result as *mut c_int,
                                 &mut error as *mut c_int,
                                 path,
                                 buf);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn lseek(fd: c_int, offset: off_t, whence: c_int) -> off_t {
    let mut result: off_t = 0;
    let mut error: c_int = 0;
    let status = u_lseek_ocall(&mut result as *mut off_t,
                               &mut error as *mut c_int,
                               fd,
                               offset,
                               whence);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn lseek64(fd: c_int, offset: off64_t, whence: c_int) -> off64_t {
    let mut result: off64_t = 0;
    let mut error: c_int = 0;
    let status = u_lseek64_ocall(&mut result as *mut off64_t,
                                 &mut error as *mut c_int,
                                 fd,
                                 offset,
                                 whence);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn ftruncate(fd: c_int, length: off_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_ftruncate_ocall(&mut result as *mut c_int,
                                   &mut error as *mut c_int,
                                   fd,
                                   length);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn ftruncate64(fd: c_int, length: off64_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_ftruncate64_ocall(&mut result as *mut c_int,
                                     &mut error as *mut c_int,
                                     fd,
                                     length);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn truncate(path: *const c_char, length: off_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_truncate_ocall(&mut result as *mut c_int,
                                  &mut error as *mut c_int,
                                  path,
                                  length);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn truncate64(path: *const c_char, length: off64_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_truncate64_ocall(&mut result as *mut c_int,
                                    &mut error as *mut c_int,
                                    path,
                                    length);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn fsync(fd: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_fsync_ocall(&mut result as *mut c_int,
                               &mut error as *mut c_int,
                               fd);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn fdatasync(fd: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_fdatasync_ocall(&mut result as *mut c_int,
                                   &mut error as *mut c_int,
                                   fd);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn fchmod(fd: c_int, mode: mode_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_fchmod_ocall(&mut result as *mut c_int,
                                &mut error as *mut c_int,
                                fd,
                                mode);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn unlink(pathname: *const c_char) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_unlink_ocall(&mut result as *mut c_int,
                                &mut error as *mut c_int,
                                pathname);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn link(oldpath: *const c_char, newpath: *const c_char) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_link_ocall(&mut result as *mut c_int,
                              &mut error as *mut c_int,
                              oldpath,
                              newpath);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn rename(oldpath: *const c_char, newpath: *const c_char) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_rename_ocall(&mut result as *mut c_int,
                                &mut error as *mut c_int,
                                oldpath,
                                newpath);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn chmod(path: *const c_char, mode: mode_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_chmod_ocall(&mut result as *mut c_int,
                               &mut error as *mut c_int,
                               path,
                               mode);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn readlink(path: *const c_char, buf: *mut c_char, bufsz: size_t) -> ssize_t {
    let mut result: ssize_t = 0;
    let mut error: c_int = 0;
    let status = u_readlink_ocall(&mut result as *mut ssize_t,
                                  &mut error as *mut c_int,
                                  path,
                                  buf,
                                  bufsz);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn symlink(path1: *const c_char, path2: *const c_char) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_symlink_ocall(&mut result as *mut c_int,
                                 &mut error as *mut c_int,
                                 path1,
                                 path2);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn realpath(pathname: *const c_char) -> *mut c_char {
    let mut result: *mut c_char = ptr::null_mut();
    let mut error: c_int = 0;
    let status = u_realpath_ocall(&mut result as *mut *mut c_char,
                                  &mut error as *mut c_int,
                                  pathname);

    if status == sgx_status_t::SGX_SUCCESS {
        if result.is_null() {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = ptr::null_mut();
    }
    result
}

pub unsafe fn mkdir(pathname: *const c_char, mode: mode_t) -> c_int {
    let mut error: c_int = 0;
    let mut result: c_int = 0;
    let status = u_mkdir_ocall(&mut result as *mut c_int,
                               &mut error as *mut c_int,
                               pathname,
                               mode);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn rmdir(pathname: *const c_char) -> c_int {
    let mut error: c_int = 0;
    let mut result: c_int = 0;
    let status = u_rmdir_ocall(&mut result as *mut c_int,
                               &mut error as *mut c_int,
                               pathname);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn opendir(pathname: *const c_char) -> *mut DIR {
    let mut result: *mut DIR = ptr::null_mut();
    let mut error: c_int = 0;
    let status = u_opendir_ocall(&mut result as *mut *mut DIR,
                                 &mut error as *mut c_int,
                                 pathname);

    if status == sgx_status_t::SGX_SUCCESS {
        if result.is_null() {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = ptr::null_mut();
    }
    result
}

pub unsafe fn readdir64_r(dirp: *mut DIR,
                          entry: *mut dirent64,
                          dirresult: *mut *mut dirent64) -> c_int {
    let mut result: c_int = 0;
    let status = u_readdir64_r_ocall(&mut result as *mut c_int,
                                     dirp,
                                     entry,
                                     dirresult);
    if status == sgx_status_t::SGX_SUCCESS && result == 0 {
        let dir_ret = *dirresult;
        if !dir_ret.is_null() {
            *dirresult = entry;
        }
    } else {
        *dirresult = ptr::null_mut();
        if status != sgx_status_t::SGX_SUCCESS {
            result = ESGX;
        }
    }
    result
}
                           
pub unsafe fn closedir(dirp: *mut DIR) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_closedir_ocall(&mut result as *mut c_int,
                                  &mut error as *mut c_int,
                                  dirp);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}   

pub unsafe fn dirfd(dirp: *mut DIR) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_dirfd_ocall(&mut result as *mut c_int,
                               &mut error as *mut c_int,
                               dirp);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn fstatat64(dirfd: c_int,
                        pathname: *const c_char,
                        buf: *mut stat64,
                        flags: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_fstatat64_ocall(&mut result as *mut c_int,
                                   &mut error as *mut c_int,
                                   dirfd,
                                   pathname,
                                   buf,
                                   flags);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t {
    let mut result: ssize_t = 0;
    let mut error: c_int = 0;

    if buf.is_null() || sgx_is_within_enclave(buf, count) == 0 {
        set_errno(EINVAL);
        return -1;
    }
    if count >= usize::max_value() {
        set_errno(EINVAL);
        return -1;
    }

    let tmp_buf = if count <= MAX_OCALL_ALLOC_SIZE {
        sgx_ocalloc(count)
    } else {
        malloc(count)
    };
    if tmp_buf.is_null() {
        set_errno(ENOMEM );
        return -1;
    }
    tmp_buf.write_bytes(0_u8, count);

    let status = u_read_ocall(&mut result as *mut ssize_t,
                              &mut error as *mut c_int,
                              fd,
                              tmp_buf,
                              count);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    if result != -1 {
        ptr::copy_nonoverlapping(tmp_buf as *const u8, buf as *mut u8, count);
    }
    if count <= MAX_OCALL_ALLOC_SIZE {
        sgx_ocfree();
    } else {
        free(tmp_buf);
    }
    result
}

pub unsafe fn pread64(fd: c_int, buf: *mut c_void, count: size_t, offset: off64_t) -> ssize_t {
    let mut result: ssize_t = 0;
    let mut error: c_int = 0;

    if buf.is_null() || sgx_is_within_enclave(buf, count) == 0 {
        set_errno(EINVAL);
        return -1;
    }
    if count >= usize::max_value() {
        set_errno(EINVAL);
        return -1;
    }

    let tmp_buf = if count <= MAX_OCALL_ALLOC_SIZE {
        sgx_ocalloc(count)
    } else {
        malloc(count)
    };
    if tmp_buf.is_null() {
        set_errno(ENOMEM );
        return -1;
    }
    tmp_buf.write_bytes(0_u8, count);

    let status = u_pread64_ocall(&mut result as *mut ssize_t,
                                 &mut error as *mut c_int,
                                 fd,
                                 tmp_buf,
                                 count,
                                 offset);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    if result != -1 {
        ptr::copy_nonoverlapping(tmp_buf as *const u8, buf as *mut u8, count);
    }
    if count <= MAX_OCALL_ALLOC_SIZE {
        sgx_ocfree();
    } else {
        free(tmp_buf);
    }
    result
}

pub unsafe fn readv(fd: c_int, iov: *const iovec, iovcnt: c_int) -> ssize_t {
    let mut result: ssize_t = 0;
    let mut error: c_int = 0;
    let mut ptr: *mut u8 = ptr::null_mut();
    let mut iosize: usize = 0;

    if iov.is_null() || iovcnt <= 0 ||
       sgx_is_within_enclave(iov as *const c_void, iovcnt as usize * mem::size_of::<iovec>()) == 0 {
        set_errno(EINVAL);
        return -1;
    }

    let v = slice::from_raw_parts(iov, iovcnt as usize);
    for io in v {
        if !io.iov_base.is_null() && io.iov_len > 0 &&
            sgx_is_within_enclave(io.iov_base, io.iov_len as usize) != 0 {
            iosize += io.iov_len as usize;
        } else {
            set_errno(EINVAL);
            return -1;
        }
    }

    let iobase = malloc(iosize) as *mut u8;
    if iobase.is_null() {
        set_errno(ENOMEM );
        return -1;
    }
    iobase.write_bytes(0_u8, iosize);

    let mut tmpiovec: Vec<iovec> = Vec::with_capacity(iovcnt as usize);
    ptr = iobase;
    for io in v {
        let tmpiov = iovec{iov_base: ptr as *mut c_void,
                           iov_len: io.iov_len};
        tmpiovec.push(tmpiov);
        ptr = ptr.add(io.iov_len as usize);
    }

    let status = u_readv_ocall(&mut result as *mut ssize_t,
                               &mut error as *mut c_int,
                               fd,
                               tmpiovec.as_slice().as_ptr(),
                               iovcnt);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    if result != -1 {
        for i in 0..v.len() {
            ptr::copy_nonoverlapping(tmpiovec[i].iov_base as *const u8, v[i].iov_base as *mut u8, v[i].iov_len as usize);
        }
    }

    free(iobase as *mut c_void);
    result
}

pub unsafe fn preadv64(fd: c_int, iov: *const iovec, iovcnt: c_int, offset: off64_t) -> ssize_t {
    let mut result: ssize_t = 0;
    let mut error: c_int = 0;
    let mut ptr: *mut u8 = ptr::null_mut();
    let mut iosize: usize = 0;

    if iov.is_null() || iovcnt <= 0 ||
       sgx_is_within_enclave(iov as *const c_void, iovcnt as usize * mem::size_of::<iovec>()) == 0 {
        set_errno(EINVAL);
        return -1;
    }

    let v = slice::from_raw_parts(iov, iovcnt as usize);
    for io in v {
        if !io.iov_base.is_null() && io.iov_len > 0 &&
            sgx_is_within_enclave(io.iov_base, io.iov_len as usize) != 0 {
            iosize += io.iov_len as usize;
        } else {
            set_errno(EINVAL);
            return -1;
        }
    }

    let iobase = malloc(iosize) as *mut u8;
    if iobase.is_null() {
        set_errno(ENOMEM );
        return -1;
    }
    iobase.write_bytes(0_u8, iosize);

    let mut tmpiovec: Vec<iovec> = Vec::with_capacity(iovcnt as usize);
    ptr = iobase;
    for io in v {
        let tmpiov = iovec{iov_base: ptr as *mut c_void,
                           iov_len: io.iov_len};
        tmpiovec.push(tmpiov);
        ptr = ptr.add(io.iov_len as usize);
    }

    let status = u_preadv64_ocall(&mut result as *mut ssize_t,
                               &mut error as *mut c_int,
                               fd,
                               tmpiovec.as_slice().as_ptr(),
                               iovcnt,
                               offset);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    if result != -1 {
        for i in 0..v.len() {
            ptr::copy_nonoverlapping(tmpiovec[i].iov_base as *const u8, v[i].iov_base as *mut u8, v[i].iov_len as usize);
        }
    }

    free(iobase as *mut c_void);
    result
}

pub unsafe fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t {
    let mut result: ssize_t = 0;
    let mut error: c_int = 0;

    if buf.is_null() || sgx_is_within_enclave(buf, count) == 0 {
        set_errno(EINVAL);
        return -1;
    }
    if count >= usize::max_value() {
        set_errno(EINVAL);
        return -1;
    }

    let tmp_buf = if count <= MAX_OCALL_ALLOC_SIZE {
        sgx_ocalloc(count)
    } else {
        malloc(count)
    };
    if tmp_buf.is_null() {
        set_errno(ENOMEM );
        return -1;
    }
    ptr::copy_nonoverlapping(buf as *const u8, tmp_buf as *mut u8, count);

    let status = u_write_ocall(&mut result as *mut ssize_t,
                               &mut error as *mut c_int,
                               fd,
                               tmp_buf,
                               count);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    if count <= MAX_OCALL_ALLOC_SIZE {
        sgx_ocfree();
    } else {
        free(tmp_buf);
    }
    result
}

pub unsafe fn pwrite64(fd: c_int, buf: *const c_void, count: size_t, offset: off64_t) -> ssize_t {
    let mut result: ssize_t = 0;
    let mut error: c_int = 0;

    if buf.is_null() || sgx_is_within_enclave(buf, count) == 0 {
        set_errno(EINVAL);
        return -1;
    }
    if count >= usize::max_value() {
        set_errno(EINVAL);
        return -1;
    }

    let tmp_buf = if count <= MAX_OCALL_ALLOC_SIZE {
        sgx_ocalloc(count)
    } else {
        malloc(count)
    };
    if tmp_buf.is_null() {
        set_errno(ENOMEM );
        return -1;
    }
    ptr::copy_nonoverlapping(buf as *const u8, tmp_buf as *mut u8, count);

    let status = u_pwrite64_ocall(&mut result as *mut ssize_t,
                                  &mut error as *mut c_int,
                                  fd,
                                  tmp_buf,
                                  count,
                                  offset);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    if count <= MAX_OCALL_ALLOC_SIZE {
        sgx_ocfree();
    } else {
        free(tmp_buf);
    }
    result
}

pub unsafe fn writev(fd: c_int, iov: *const iovec, iovcnt: c_int) -> ssize_t {
    let mut result: ssize_t = 0;
    let mut error: c_int = 0;
    let mut ptr: *mut u8 = ptr::null_mut();
    let mut iosize: usize = 0;

    if iov.is_null() || iovcnt <= 0 ||
       sgx_is_within_enclave(iov as *const c_void, iovcnt as usize * mem::size_of::<iovec>()) == 0 {
        set_errno(EINVAL);
        return -1;
    }

    let v = slice::from_raw_parts(iov, iovcnt as usize);
    for io in v {
        if !io.iov_base.is_null() && io.iov_len > 0 &&
            sgx_is_within_enclave(io.iov_base, io.iov_len as usize) != 0 {
            iosize += io.iov_len as usize;
        } else {
            set_errno(EINVAL);
            return -1;
        }
    }

    let iobase = malloc(iosize) as *mut u8;
    if iobase.is_null() {
        set_errno(ENOMEM );
        return -1;
    }
    iobase.write_bytes(0_u8, iosize);

    let mut tmpiovec: Vec<iovec> = Vec::with_capacity(iovcnt as usize);
    ptr = iobase;
    for io in v {
        let tmpiov = iovec{iov_base: ptr as *mut c_void,
                           iov_len: io.iov_len};
        ptr::copy_nonoverlapping(io.iov_base as *const u8, tmpiov.iov_base as *mut u8, io.iov_len as usize);
        tmpiovec.push(tmpiov);
        ptr = ptr.add(io.iov_len as usize);
    }

    let status = u_writev_ocall(&mut result as *mut ssize_t,
                                &mut error as *mut c_int,
                                fd,
                                tmpiovec.as_slice().as_ptr(),
                                iovcnt);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    free(iobase as *mut c_void);
    result
}

pub unsafe fn pwritev64(fd: c_int, iov: *const iovec, iovcnt: c_int, offset: off64_t) -> ssize_t {
    let mut result: ssize_t = 0;
    let mut error: c_int = 0;
    let mut ptr: *mut u8 = ptr::null_mut();
    let mut iosize: usize = 0;

    if iov.is_null() || iovcnt <= 0 ||
       sgx_is_within_enclave(iov as *const c_void, iovcnt as usize * mem::size_of::<iovec>()) ==0 {
        set_errno(EINVAL);
        return -1;
    }

    let v = slice::from_raw_parts(iov, iovcnt as usize);
    for io in v {
        if !io.iov_base.is_null() && io.iov_len > 0 &&
            sgx_is_within_enclave(io.iov_base, io.iov_len as usize) != 0 {
            iosize += io.iov_len as usize;
        } else {
            set_errno(EINVAL);
            return -1;
        }
    }

    let iobase = malloc(iosize) as *mut u8;
    if iobase.is_null() {
        set_errno(ENOMEM );
        return -1;
    }
    iobase.write_bytes(0_u8, iosize);

    let mut tmpiovec: Vec<iovec> = Vec::with_capacity(iovcnt as usize);
    ptr = iobase;
    for io in v {
        let tmpiov = iovec{iov_base: ptr as *mut c_void,
                           iov_len: io.iov_len};
        ptr::copy_nonoverlapping(io.iov_base as *const u8, tmpiov.iov_base as *mut u8, io.iov_len as usize);
        tmpiovec.push(tmpiov);
        ptr = ptr.add(io.iov_len as usize);
    }

    let status = u_pwritev64_ocall(&mut result as *mut ssize_t,
                                   &mut error as *mut c_int,
                                   fd,
                                   tmpiovec.as_slice().as_ptr(),
                                   iovcnt,
                                   offset);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    free(iobase as *mut c_void);
    result
}

pub unsafe fn fcntl_arg0(fd: c_int, cmd: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_fcntl_arg0_ocall(&mut result as *mut c_int,
                                    &mut error as *mut c_int,
                                    fd,
                                    cmd);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn fcntl_arg1(fd: c_int, cmd: c_int, arg: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_fcntl_arg1_ocall(&mut result as *mut c_int,
                                    &mut error as *mut c_int,
                                    fd,
                                    cmd,
                                    arg);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn ioctl_arg0(fd: c_int, request: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_ioctl_arg0_ocall(&mut result as *mut c_int,
                                    &mut error as *mut c_int,
                                    fd,
                                    request);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn ioctl_arg1(fd: c_int, request: c_int, arg: *mut c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_ioctl_arg1_ocall(&mut result as *mut c_int,
                                    &mut error as *mut c_int,
                                    fd,
                                    request,
                                    arg);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn close(fd: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_close_ocall(&mut result as *mut c_int,
                               &mut error as *mut c_int,
                               fd);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn clock_gettime(clk_id: clockid_t, tp: *mut timespec) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_clock_gettime_ocall(&mut result as *mut c_int,
                                       &mut error as *mut c_int,
                                       clk_id,
                                       tp);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_socket_ocall(&mut result as *mut c_int,
                                &mut error as *mut c_int,
                                domain,
                                ty,
                                protocol);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn socketpair(domain: c_int, ty: c_int, protocol: c_int, sv: *mut c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_socketpair_ocall(&mut result as *mut c_int,
                                    &mut error as *mut c_int,
                                    domain,
                                    ty,
                                    protocol,
                                    sv);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn bind(sockfd: c_int, address: *const sockaddr, addrlen: socklen_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_bind_ocall(&mut result as *mut c_int,
                              &mut error as *mut c_int,
                              sockfd,
                              address,
                              addrlen);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn listen(sockfd: c_int, backlog: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_listen_ocall(&mut result as *mut c_int,
                                &mut error as *mut c_int,
                                sockfd,
                                backlog);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn accept(sockfd: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let len_in: socklen_t = if !addrlen.is_null() { *addrlen } else { 0 };
    let mut len_out: socklen_t = 0 as socklen_t;
    let status = u_accept_ocall(&mut result as *mut c_int,
                                &mut error as *mut c_int,
                                sockfd,
                                addr,
                                len_in, // This additional arg is just for EDL
                                &mut len_out as *mut socklen_t);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    if !addrlen.is_null() {
        *addrlen = len_out;
    }
    result
}

pub unsafe fn accept4(sockfd: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t, flags: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let len_in: socklen_t = if !addrlen.is_null() { *addrlen } else { 0 };
    let mut len_out: socklen_t = 0 as socklen_t;
    let status = u_accept4_ocall(&mut result as *mut c_int,
                                 &mut error as *mut c_int,
                                 sockfd,
                                 addr,
                                 len_in, // This additional arg is just for EDL
                                 &mut len_out as *mut socklen_t,
                                 flags);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    if !addrlen.is_null() {
        *addrlen = len_out;
    }
    result
}

pub unsafe fn connect(sockfd: c_int, address: *const sockaddr, addrlen: socklen_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_connect_ocall(&mut result as *mut c_int,
                                 &mut error as *mut c_int,
                                 sockfd,
                                 address,
                                 addrlen);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn send(sockfd: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t {
    let mut result: ssize_t = 0;
    let mut error: c_int = 0;

    if buf.is_null() || sgx_is_within_enclave(buf, len) == 0 {
        set_errno(EINVAL);
        return -1;
    }
    if len >= usize::max_value() {
        set_errno(EINVAL);
        return -1;
    }

    let tmp_buf = if len <= MAX_OCALL_ALLOC_SIZE {
        sgx_ocalloc(len)
    } else {
        malloc(len)
    };
    if tmp_buf.is_null() {
        set_errno(ENOMEM );
        return -1;
    }
    ptr::copy_nonoverlapping(buf as *const u8, tmp_buf as *mut u8, len);

    let status = u_send_ocall(&mut result as *mut ssize_t,
                              &mut error as *mut c_int,
                              sockfd,
                              tmp_buf,
                              len,
                              flags);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    if len <= MAX_OCALL_ALLOC_SIZE {
        sgx_ocfree();
    } else {
        free(tmp_buf);
    }
    result
}

pub unsafe fn sendto(sockfd: c_int,
                     buf: *const c_void,
                     len: size_t,
                     flags: c_int,
                     addr: *const sockaddr,
                     addrlen: socklen_t) -> ssize_t {
    let mut result: ssize_t = 0;
    let mut error: c_int = 0;

    if buf.is_null() || sgx_is_within_enclave(buf, len) == 0 {
        set_errno(EINVAL);
        return -1;
    }
    if len >= usize::max_value() {
        set_errno(EINVAL);
        return -1;
    }

    let tmp_buf = if len <= MAX_OCALL_ALLOC_SIZE {
        sgx_ocalloc(len)
    } else {
        malloc(len)
    };
    if tmp_buf.is_null() {
        set_errno(ENOMEM );
        return -1;
    }
    ptr::copy_nonoverlapping(buf as *const u8, tmp_buf as *mut u8, len);

    let status = u_sendto_ocall(&mut result as *mut ssize_t,
                                &mut error as *mut c_int,
                                sockfd,
                                tmp_buf,
                                len,
                                flags,
                                addr,
                                addrlen);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    if len <= MAX_OCALL_ALLOC_SIZE {
        sgx_ocfree();
    } else {
        free(tmp_buf);
    }
    result
}

pub unsafe fn sendmsg(sockfd: c_int, msg: *const msghdr, flags: c_int) -> ssize_t {
    let mut result: ssize_t = 0;
    let mut error: c_int = 0;
    let mut hdrsize: usize = 0;
    let mut ptr: *mut u8 = ptr::null_mut();

    if msg.is_null() || sgx_is_within_enclave(msg as *const c_void, mem::size_of::<msghdr>()) == 0 {
        set_errno(EINVAL);
        return -1;
    }

    let mhdr: &msghdr = &*msg;
    if !mhdr.msg_name.is_null() && mhdr.msg_namelen > 0 &&
        sgx_is_within_enclave(mhdr.msg_name, mhdr.msg_namelen as usize) != 0 {
        hdrsize += mhdr.msg_namelen as usize;
    }

    if !mhdr.msg_iov.is_null() && mhdr.msg_iovlen > 0 &&
       sgx_is_within_enclave(mhdr.msg_iov as *const c_void, mhdr.msg_iovlen as usize * mem::size_of::<iovec>()) != 0 {

        hdrsize += mhdr.msg_iovlen as usize * mem::size_of::<iovec>();
        let v = slice::from_raw_parts(mhdr.msg_iov, mhdr.msg_iovlen as usize);
        for io in v {
            if !io.iov_base.is_null() && io.iov_len > 0 &&
                sgx_is_within_enclave(io.iov_base, io.iov_len as usize) != 0 {
                hdrsize += io.iov_len as usize;
            } else {
                set_errno(EINVAL);
                return -1;
            }
        }
    }

    if !mhdr.msg_control.is_null() &&  mhdr.msg_controllen > 0 &&
        sgx_is_within_enclave(mhdr.msg_control, mhdr.msg_controllen as usize) != 0 {
        hdrsize += mhdr.msg_controllen as usize;
    }

    let hdrbase = malloc(hdrsize) as *mut u8;
    if hdrbase.is_null() {
        set_errno(ENOMEM );
        return -1;
    }
    hdrbase.write_bytes(0_u8, hdrsize);

    let mut tmpmsg: msghdr = mem::zeroed();
    ptr = hdrbase;
    if !mhdr.msg_name.is_null() && mhdr.msg_namelen > 0 {
        tmpmsg.msg_name = ptr as *mut c_void;
        tmpmsg.msg_namelen = mhdr.msg_namelen;
        ptr::copy_nonoverlapping(mhdr.msg_name as *const u8, tmpmsg.msg_name as *mut u8, mhdr.msg_namelen as usize);
        ptr = ptr.add(mhdr.msg_namelen as usize);
    }

    if !mhdr.msg_iov.is_null() && mhdr.msg_iovlen > 0 {
        let tmpiov = slice::from_raw_parts_mut(ptr as *mut iovec, mhdr.msg_iovlen as usize);
        ptr = ptr.add(mhdr.msg_iovlen as usize * mem::size_of::<iovec>());

        let v = slice::from_raw_parts(mhdr.msg_iov, mhdr.msg_iovlen as usize);
        for i in 0..v.len() {
            tmpiov[i].iov_base = ptr as *mut c_void;
            tmpiov[i].iov_len = v[i].iov_len;
            ptr::copy_nonoverlapping(v[i].iov_base as *const u8, tmpiov[i].iov_base as *mut u8, v[i].iov_len as usize);
            ptr = ptr.add(v[i].iov_len as usize);
        }
    }

    if !mhdr.msg_control.is_null() &&  mhdr.msg_controllen > 0 {
        tmpmsg.msg_control = ptr as *mut c_void;
        tmpmsg.msg_controllen = mhdr.msg_controllen;
        ptr::copy_nonoverlapping(mhdr.msg_control as *const u8, tmpmsg.msg_control as *mut u8, mhdr.msg_controllen as usize);
    }

    let status = u_sendmsg_ocall(&mut result as *mut ssize_t,
                                 &mut error as *mut c_int,
                                 sockfd,
                                 &tmpmsg as *const msghdr,
                                 flags);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    free(hdrbase as *mut c_void);
    result
}

pub unsafe fn recv(sockfd: c_int, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t {
    let mut result: ssize_t = 0;
    let mut error: c_int = 0;

    if buf.is_null() || sgx_is_within_enclave(buf, len) == 0 {
        set_errno(EINVAL);
        return -1;
    }
    if len >= usize::max_value() {
        set_errno(EINVAL);
        return -1;
    }

    let tmp_buf = if len <= MAX_OCALL_ALLOC_SIZE {
        sgx_ocalloc(len)
    } else {
        malloc(len)
    };
    if tmp_buf.is_null() {
        set_errno(ENOMEM );
        return -1;
    }
    tmp_buf.write_bytes(0_u8, len);

    let status = u_recv_ocall(&mut result as *mut ssize_t,
                              &mut error as *mut c_int,
                              sockfd,
                              tmp_buf,
                              len,
                              flags);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    if result != -1 {
        ptr::copy_nonoverlapping(tmp_buf as *const u8, buf as *mut u8, len);
    }
    if len <= MAX_OCALL_ALLOC_SIZE {
        sgx_ocfree();
    } else {
        free(tmp_buf);
    }
    result
}

pub unsafe fn recvfrom(sockfd: c_int,
                       buf: *mut c_void,
                       len: size_t,
                       flags: c_int,
                       addr: *mut sockaddr,
                       addrlen: *mut socklen_t) -> ssize_t {
    let mut result: ssize_t = 0;
    let mut error: c_int = 0;
    let len_in: socklen_t = if !addrlen.is_null() { *addrlen } else { 0 };
    let mut len_out: socklen_t = 0 as socklen_t;

    if buf.is_null() || sgx_is_within_enclave(buf, len) == 0 {
        set_errno(EINVAL);
        return -1;
    }
    if len >= usize::max_value() {
        set_errno(EINVAL);
        return -1;
    }

    let tmp_buf = if len <= MAX_OCALL_ALLOC_SIZE {
        sgx_ocalloc(len)
    } else {
        malloc(len)
    };
    if tmp_buf.is_null() {
        set_errno(ENOMEM );
        return -1;
    }
    tmp_buf.write_bytes(0_u8, len);

    let status = u_recvfrom_ocall(&mut result as *mut ssize_t,
                                  &mut error as *mut c_int,
                                  sockfd,
                                  tmp_buf,
                                  len,
                                  flags,
                                  addr,
                                  len_in, // This additional arg is just for EDL
                                  &mut len_out as *mut socklen_t);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    if result != -1 {
        ptr::copy_nonoverlapping(tmp_buf as *const u8, buf as *mut u8, len);
    }
    if len <= MAX_OCALL_ALLOC_SIZE {
        sgx_ocfree();
    } else {
        free(tmp_buf);
    }

    if !addrlen.is_null() {
        *addrlen = len_out;
    }
    result
}

pub unsafe fn recvmsg(sockfd: c_int, msg: *mut msghdr, flags: c_int) -> ssize_t {
    let mut result: ssize_t = 0;
    let mut error: c_int = 0;
    let mut hdrsize: usize = 0;
    let mut ptr: *mut u8 = ptr::null_mut();

    if msg.is_null() || sgx_is_within_enclave(msg as *const c_void, mem::size_of::<msghdr>()) == 0 {
        set_errno(EINVAL);
        return -1;
    }

    let mhdr: &mut msghdr = &mut *msg;
    if !mhdr.msg_name.is_null() && mhdr.msg_namelen > 0 &&
        sgx_is_within_enclave(mhdr.msg_name, mhdr.msg_namelen as usize) != 0 {
        hdrsize += mhdr.msg_namelen as usize;
    }

    if !mhdr.msg_iov.is_null() && mhdr.msg_iovlen > 0 &&
       sgx_is_within_enclave(mhdr.msg_iov as *const c_void, mhdr.msg_iovlen as usize * mem::size_of::<iovec>()) != 0 {

        hdrsize += mhdr.msg_iovlen as usize * mem::size_of::<iovec>();
        let v = slice::from_raw_parts(mhdr.msg_iov, mhdr.msg_iovlen as usize);
        for io in v {
            if !io.iov_base.is_null() && io.iov_len > 0 &&
                sgx_is_within_enclave(io.iov_base, io.iov_len as usize) != 0 {
                hdrsize += io.iov_len as usize;
            } else {
                set_errno(EINVAL);
                return -1;
            }
        }
    }

    if !mhdr.msg_control.is_null() &&  mhdr.msg_controllen > 0 &&
        sgx_is_within_enclave(mhdr.msg_control, mhdr.msg_controllen as usize) != 0 {
        hdrsize += mhdr.msg_controllen as usize;
    }

    let hdrbase = malloc(hdrsize) as *mut u8;
    if hdrbase.is_null() {
        set_errno(ENOMEM );
        return -1;
    }
    hdrbase.write_bytes(0_u8, hdrsize);

    let mut tmpmsg: msghdr = mem::zeroed();
    ptr = hdrbase;
    if !mhdr.msg_name.is_null() && mhdr.msg_namelen > 0 {
        tmpmsg.msg_name = ptr as *mut c_void;
        tmpmsg.msg_namelen = mhdr.msg_namelen;
        ptr::copy_nonoverlapping(mhdr.msg_name as *const u8, tmpmsg.msg_name as *mut u8, mhdr.msg_namelen as usize);
        ptr = ptr.add(mhdr.msg_namelen as usize);
    }

    if !mhdr.msg_iov.is_null() && mhdr.msg_iovlen > 0 {
        let tmpiov = slice::from_raw_parts_mut(ptr as *mut iovec, mhdr.msg_iovlen as usize);
        ptr = ptr.add(mhdr.msg_iovlen as usize * mem::size_of::<iovec>());

        let v = slice::from_raw_parts(mhdr.msg_iov, mhdr.msg_iovlen as usize);
        for i in 0..v.len() {
            tmpiov[i].iov_base = ptr as *mut c_void;
            tmpiov[i].iov_len = v[i].iov_len;
            ptr = ptr.add(v[i].iov_len as usize);
        }
    }

    if !mhdr.msg_control.is_null() &&  mhdr.msg_controllen > 0 {
        tmpmsg.msg_control = ptr as *mut c_void;
        tmpmsg.msg_controllen = mhdr.msg_controllen;
        ptr::copy_nonoverlapping(mhdr.msg_control as *const u8, tmpmsg.msg_control as *mut u8, mhdr.msg_controllen as usize);
    }

    let status = u_recvmsg_ocall(&mut result as *mut ssize_t,
                                 &mut error as *mut c_int,
                                 sockfd,
                                 &mut tmpmsg as *mut msghdr,
                                 flags);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    ptr = hdrbase;
    if !mhdr.msg_name.is_null() && mhdr.msg_namelen > 0 {
        ptr = ptr.add(mhdr.msg_namelen as usize);
    }

    if !mhdr.msg_iov.is_null() && mhdr.msg_iovlen > 0 {
        let tmpiov = slice::from_raw_parts_mut(ptr as *mut iovec, mhdr.msg_iovlen as usize);
        ptr = ptr.add(mhdr.msg_iovlen as usize * mem::size_of::<iovec>());

        let v = slice::from_raw_parts(mhdr.msg_iov, mhdr.msg_iovlen as usize);
        for i in 0..v.len() {
            ptr::copy_nonoverlapping(tmpiov[i].iov_base as *const u8, v[i].iov_base as *mut u8, v[i].iov_len as usize);
            ptr = ptr.add(v[i].iov_len as usize);
        }
    }

    if !mhdr.msg_control.is_null() &&  mhdr.msg_controllen > 0 {
        ptr::copy_nonoverlapping(tmpmsg.msg_control as *const u8, mhdr.msg_control as *mut u8, mhdr.msg_controllen as usize);
    }

    free(hdrbase as *mut c_void);
    result
}

pub unsafe fn setsockopt(sockfd: c_int,
                         level: c_int,
                         optname: c_int,
                         optval: *const c_void,
                         optlen: socklen_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_setsockopt_ocall(&mut result as *mut c_int,
                                    &mut error as *mut c_int,
                                    sockfd,
                                    level,
                                    optname,
                                    optval,
                                    optlen);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn getsockopt(sockfd: c_int,
                         level: c_int,
                         optname: c_int,
                         optval: *mut c_void,
                         optlen: *mut socklen_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let len_in: socklen_t = if !optlen.is_null() { *optlen } else { 0 };
    let mut len_out: socklen_t = 0 as socklen_t;

    let status = u_getsockopt_ocall(&mut result as *mut c_int,
                                    &mut error as *mut c_int,
                                    sockfd,
                                    level,
                                    optname,
                                    optval,
                                    len_in,
                                    &mut len_out as *mut socklen_t);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    if !optlen.is_null() {
        *optlen = len_out;
    }
    result
}

pub unsafe fn getpeername(sockfd: c_int, address: *mut sockaddr, addrlen: *mut socklen_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let len_in: socklen_t = if !addrlen.is_null() { *addrlen } else { 0 };
    let mut len_out: socklen_t = 0 as socklen_t;
    let status = u_getpeername_ocall(&mut result as *mut c_int,
                                     &mut error as *mut c_int,
                                     sockfd,
                                     address,
                                     len_in,
                                     &mut len_out as *mut socklen_t);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    if !addrlen.is_null() {
        *addrlen = len_out;
    }
    result
}

pub unsafe fn getsockname(sockfd: c_int, address: *mut sockaddr, addrlen: *mut socklen_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let len_in: socklen_t = if !addrlen.is_null() { *addrlen } else { 0 };
    let mut len_out: socklen_t = 0 as socklen_t;
    let status = u_getsockname_ocall(&mut result as *mut c_int,
                                     &mut error as *mut c_int,
                                     sockfd,
                                     address,
                                     len_in,
                                     &mut len_out as *mut socklen_t);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }

    if !addrlen.is_null() {
        *addrlen = len_out;
    }
    result
}

pub unsafe fn shutdown(sockfd: c_int, how: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_shutdown_ocall(&mut result as *mut c_int,
                                  &mut error as *mut c_int,
                                  sockfd,
                                  how);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn getaddrinfo(node: *const c_char,
                          service: *const c_char,
                          hints: *const addrinfo,
                          res: *mut *mut addrinfo) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let mut ret_res: *mut addrinfo = ptr::null_mut();
    let hint: addrinfo = if !hints.is_null() {
        addrinfo {
            ai_flags: (*hints).ai_flags,
            ai_family: (*hints).ai_family,
            ai_socktype: (*hints).ai_socktype,
            ai_protocol: (*hints).ai_protocol,
            ai_addrlen: 0,
            ai_addr: ptr::null_mut(),
            ai_canonname: ptr::null_mut(),
            ai_next: ptr::null_mut(),
        }
    } else {
        addrinfo {
            ai_flags: AI_V4MAPPED | AI_ADDRCONFIG,
            ai_family: AF_UNSPEC,
            ai_socktype: 0,
            ai_protocol: 0,
            ai_addrlen: 0,
            ai_addr: ptr::null_mut(),
            ai_canonname: ptr::null_mut(),
            ai_next: ptr::null_mut(),
        }
    };

    let status = u_getaddrinfo_ocall(&mut result as *mut c_int,
                                     &mut error as *mut c_int,
                                     node,
                                     service,
                                     &hint as *const addrinfo,
                                     &mut ret_res as *mut *mut addrinfo);
    if status == sgx_status_t::SGX_SUCCESS {
        if result == 0 {
            *res = ptr::null_mut();
            let mut cur_ptr: *mut addrinfo = ret_res;
            let mut addrinfo_vec: Vec<Box<addrinfo>> = Vec::new();
            while cur_ptr != ptr::null_mut() {
                let cur: &addrinfo = &*cur_ptr;
                let mut info = addrinfo {
                    ai_flags: cur.ai_flags,
                    ai_family: cur.ai_family,
                    ai_socktype: cur.ai_socktype,
                    ai_protocol: cur.ai_protocol,
                    ai_addrlen: 0,
                    ai_addr: ptr::null_mut(),
                    ai_canonname: ptr::null_mut(),
                    ai_next: ptr::null_mut(),
                };

                if !cur.ai_addr.is_null() && cur.ai_addrlen > 0 {
                    let mut addr_vec = vec![0u8; cur.ai_addrlen as usize];
                    let addr_slice: &[u8] = slice::from_raw_parts(cur.ai_addr as *const u8, cur.ai_addrlen as usize);
                    addr_vec.copy_from_slice(addr_slice);
                    addr_vec.shrink_to_fit();
                    info.ai_addrlen = cur.ai_addrlen;
                    info.ai_addr = addr_vec.as_mut_ptr() as *mut sockaddr;
                    mem::forget(addr_vec);
                }

                if !cur.ai_canonname.is_null() {
                    let len: usize = strlen(cur.ai_canonname) + 1;
                    let mut name_vec = vec![0u8; len];
                    let name_slice: &[u8] = slice::from_raw_parts(cur.ai_canonname as *const u8, len);
                    name_vec.copy_from_slice(name_slice);
                    name_vec.shrink_to_fit();
                    info.ai_canonname = name_vec.as_mut_ptr() as *mut c_char;
                    mem::forget(name_vec);
                }

                addrinfo_vec.push(Box::new(info));
                cur_ptr = cur.ai_next;
            }

            if addrinfo_vec.len() > 0 {
                for i in 0..addrinfo_vec.len() - 1 {
                    addrinfo_vec[i].ai_next = addrinfo_vec[i + 1].as_mut() as *mut addrinfo;
                }
                let res_ptr = addrinfo_vec[0].as_mut() as *mut addrinfo;

                for info in addrinfo_vec {
                    let _ = Box::into_raw(info);
                }
                *res = res_ptr;
            }
            let _ = u_freeaddrinfo_ocall(ret_res);

        } else if result == EAI_SYSTEM {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = EAI_SYSTEM;
    }
    result
}

pub unsafe fn freeaddrinfo(res: *mut addrinfo ) {
    let mut cur_ptr: *mut addrinfo = res;
    let mut addrinfo_vec: Vec<Box<addrinfo>> = Vec::new();
    while cur_ptr != ptr::null_mut() {
        let cur: &addrinfo = &*cur_ptr;
        if !cur.ai_addr.is_null() && cur.ai_addrlen > 0 {
            let addr_vec = Vec::from_raw_parts(cur.ai_addr as *mut u8, cur.ai_addrlen as usize, cur.ai_addrlen as usize);
            drop(addr_vec);
        }
        if !cur.ai_canonname.is_null() {
            let len: usize = strlen(cur.ai_canonname) + 1;
            let name_vec = Vec::from_raw_parts(cur.ai_canonname as *mut u8, len, len);
            drop(name_vec);
        }
        addrinfo_vec.push(Box::from_raw(cur_ptr));
        cur_ptr = cur.ai_next;
    }
    drop(addrinfo_vec);
}

pub unsafe fn gai_strerror(errcode: c_int) -> *const c_char {
    let mut result: *const c_char = ptr::null();
    let status = u_gai_strerror_ocall(&mut result as *mut *const c_char, errcode);
    if status != sgx_status_t::SGX_SUCCESS {
        set_errno(ESGX);
    }
    result
}

pub unsafe fn poll(fds: *mut pollfd, nfds: nfds_t, timeout: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_poll_ocall(&mut result as *mut c_int,
                              &mut error as *mut c_int,
                              fds,
                              nfds,
                              timeout);

    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn epoll_create1(flags: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_epoll_create1_ocall(&mut result as *mut c_int,
                                       &mut error as *mut c_int,
                                       flags);
    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn epoll_ctl(epfd: c_int,
                        op: c_int,
                        fd: c_int,
                        event: *mut epoll_event) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_epoll_ctl_ocall(&mut result as *mut c_int,
                                   &mut error as *mut c_int,
                                   epfd,
                                   op,
                                   fd,
                                   event);
    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn epoll_wait(epfd: c_int,
                         events: *mut epoll_event,
                         maxevents: c_int,
                         timeout: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_epoll_wait_ocall(&mut result as *mut c_int,
                                    &mut error as *mut c_int,
                                    epfd,
                                    events,
                                    maxevents,
                                    timeout);
    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn sysconf(name: c_int) -> c_long {
    let mut result: c_long = 0;
    let mut error: c_int = 0;
    let status = u_sysconf_ocall(&mut result as *mut c_long,
                                 &mut error as *mut c_int,
                                 name);
    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn prctl(option: c_int,
                    arg2: c_ulong,
                    arg3: c_ulong,
                    arg4: c_ulong,
                    arg5: c_ulong) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_prctl_ocall(&mut result as *mut c_int,
                               &mut error as *mut c_int,
                               option,
                               arg2,
                               arg3,
                               arg4,
                               arg5);
    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn sched_setaffinity(pid: pid_t, cpusetsize: size_t, mask: *const cpu_set_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_sched_setaffinity_ocall(&mut result as *mut c_int,
                                           &mut error as *mut c_int,
                                           pid,
                                           cpusetsize,
                                           mask);
    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn sched_getaffinity(pid: pid_t, cpusetsize: size_t, mask: *mut cpu_set_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_sched_getaffinity_ocall(&mut result as *mut c_int,
                                           &mut error as *mut c_int,
                                           pid,
                                           cpusetsize,
                                           mask);
    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn pipe(fds: *mut c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_pipe_ocall(&mut result as *mut c_int,
                              &mut error as *mut c_int,
                              fds);
    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn pipe2(fds: *mut c_int, flags: c_int) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_pipe2_ocall(&mut result as *mut c_int,
                               &mut error as *mut c_int,
                               fds,
                               flags);
    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn sched_yield() -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_sched_yield_ocall(&mut result as *mut c_int,
                                     &mut error as *mut c_int);
    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn nanosleep(rqtp: *const timespec, rmtp: *mut timespec) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_nanosleep_ocall(&mut result as *mut c_int,
                                   &mut error as *mut c_int,
                                   rqtp,
                                   rmtp);
    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn sigaction(signum: c_int,
                        act: *const sigaction,
                        oldact: *mut sigaction,
                        enclave_id: uint64_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status = u_sigaction_ocall(&mut result as *mut c_int,
                                   &mut error as *mut c_int,
                                   signum,
                                   act,
                                   oldact,
                                   enclave_id);
    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn sigprocmask(signum: c_int,
                          set: *const sigset_t,
                          oldset: *mut sigset_t) -> c_int {
    let mut result: c_int = 0;
    let mut error: c_int = 0;
    let status =  u_sigprocmask_ocall(&mut result as *mut c_int,
                                      &mut error as *mut c_int,
                                      signum,
                                      set,
                                      oldset);
    if status == sgx_status_t::SGX_SUCCESS {
        if result == -1 {
            set_errno(error);
        }
    } else {
        set_errno(ESGX);
        result = -1;
    }
    result
}

pub unsafe fn raise(signum: c_int) -> c_int {
    let mut result: c_int = -1;
    let status = u_raise_ocall(&mut result as *mut c_int, signum);
    if status != sgx_status_t::SGX_SUCCESS {
       result = -1;
    }
    result
}

pub unsafe fn pthread_sigmask(signum: c_int, set: &sigset_t, oldset: &mut sigset_t) -> c_int {
    sigprocmask(signum, set, oldset)
}

pub unsafe fn getpid() -> pid_t {
    let mut result = -1;
    let status = u_getpid_ocall(&mut result as *mut pid_t);
    if status != sgx_status_t::SGX_SUCCESS {
        result = -1;
    }
    result
}
