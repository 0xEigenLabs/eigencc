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

//! Memory allocation APIs
//!
//! In a given program, the standard library has one “global” memory allocator
//! that is used for example by `Box<T>` and `Vec<T>`.
//!

use core::sync::atomic::{AtomicPtr, Ordering};
use core::{mem, ptr};
use crate::sys_common::util::dumb_print;

#[doc(inline)]
pub use alloc_crate::alloc::*;

pub use sgx_alloc::System;

static HOOK: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());

/// Registers a custom allocation error hook, replacing any that was previously registered.
///
/// The allocation error hook is invoked when an infallible memory allocation fails, before
/// the runtime aborts. The default hook prints a message to standard error,
/// but this behavior can be customized with the [`set_alloc_error_hook`] and
/// [`take_alloc_error_hook`] functions.
///
/// The hook is provided with a `Layout` struct which contains information
/// about the allocation that failed.
///
/// The allocation error hook is a global resource.
pub fn set_alloc_error_hook(hook: fn(Layout)) {
    HOOK.store(hook as *mut (), Ordering::SeqCst);
}

/// Unregisters the current allocation error hook, returning it.
///
/// *See also the function [`set_alloc_error_hook`].*
///
/// If no custom hook is registered, the default hook will be returned.
pub fn take_alloc_error_hook() -> fn(Layout) {
    let hook = HOOK.swap(ptr::null_mut(), Ordering::SeqCst);
    if hook.is_null() { default_alloc_error_hook } else { unsafe { mem::transmute(hook) } }
}

fn default_alloc_error_hook(layout: Layout) {
    dumb_print(format_args!("memory allocation of {} bytes failed", layout.size()));
}

#[doc(hidden)]
#[alloc_error_handler]
pub fn rust_oom(layout: Layout) -> ! {
    let hook = HOOK.load(Ordering::SeqCst);
    let hook: fn(Layout) =
        if hook.is_null() { default_alloc_error_hook } else { unsafe { mem::transmute(hook) } };
    hook(layout);
    unsafe { crate::sys::abort_internal() }
}

#[doc(hidden)]
#[allow(unused_attributes)]
pub mod __default_lib_allocator {
    use super::{GlobalAlloc, Layout, System};
    // These magic symbol names are used as a fallback for implementing the
    // `__rust_alloc` etc symbols (see `src/liballoc/alloc.rs`) when there is
    // no `#[global_allocator]` attribute.

    // for symbol names src/librustc_ast/expand/allocator.rs
    // for signatures src/librustc_allocator/lib.rs

    // linkage directives are provided as part of the current compiler allocator
    // ABI

    #[rustc_std_internal_symbol]
    pub unsafe extern "C" fn __rdl_alloc(size: usize, align: usize) -> *mut u8 {
        let layout = Layout::from_size_align_unchecked(size, align);
        System.alloc(layout)
    }

    #[rustc_std_internal_symbol]
    pub unsafe extern "C" fn __rdl_dealloc(ptr: *mut u8, size: usize, align: usize) {
        System.dealloc(ptr, Layout::from_size_align_unchecked(size, align))
    }

    #[rustc_std_internal_symbol]
    pub unsafe extern "C" fn __rdl_realloc(
        ptr: *mut u8,
        old_size: usize,
        align: usize,
        new_size: usize,
    ) -> *mut u8 {
        let old_layout = Layout::from_size_align_unchecked(old_size, align);
        System.realloc(ptr, old_layout, new_size)
    }

    #[rustc_std_internal_symbol]
    pub unsafe extern "C" fn __rdl_alloc_zeroed(size: usize, align: usize) -> *mut u8 {
        let layout = Layout::from_size_align_unchecked(size, align);
        System.alloc_zeroed(layout)
    }
}