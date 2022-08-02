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

use libc::{self, addrinfo, c_char, c_int};
use std::io::Error;

#[no_mangle]
pub extern "C" fn u_getaddrinfo_ocall(
    error: *mut c_int,
    node: *const c_char,
    service: *const c_char,
    hints: *const addrinfo,
    res: *mut *mut addrinfo,
) -> c_int {
    let mut errno = 0;
    let ret = unsafe { libc::getaddrinfo(node, service, hints, res) };
    if ret == libc::EAI_SYSTEM {
        errno = Error::last_os_error().raw_os_error().unwrap_or(0);
    }
    if !error.is_null() {
        unsafe {
            *error = errno;
        }
    }
    ret
}

#[no_mangle]
pub extern "C" fn u_freeaddrinfo_ocall(res: *mut addrinfo) {
    unsafe { libc::freeaddrinfo(res) }
}

#[no_mangle]
pub extern "C" fn u_gai_strerror_ocall(errcode: c_int) -> *const c_char {
    unsafe { libc::gai_strerror(errcode) }
}
