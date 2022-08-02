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

#![crate_name = "hugememsampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_types;

use sgx_types::*;
use std::string::String;
use std::vec::Vec;
use std::slice;
use std::io::{self, Write};
/// A function simply invokes ocall print to print the incoming string
///
/// # Parameters
///
/// **some_string**
///
/// A pointer to the string to be printed
///
/// **len**
///
/// An unsigned int indicates the length of str
///
/// # Return value
///
/// Always returns SGX_SUCCESS
#[no_mangle]
pub extern "C" fn say_something(some_string: *const u8, some_len: usize) -> sgx_status_t {

    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };
    let _ =  io::stdout().write(str_slice);

    // A sample &'static string
    let rust_raw_string = "This is a ";
    // An array
    let word:[u8;4] = [82, 117, 115, 116];
    // An vector
    let word_vec:Vec<u8> = vec![32, 115, 116, 114, 105, 110, 103, 33];

    // Construct a string from &'static string
    let mut hello_string = String::from(rust_raw_string);

    // Iterate on word array
    for c in word.iter() {
        hello_string.push(*c as char);
    }

    // Rust style convertion
    hello_string += String::from_utf8(word_vec).expect("Invalid UTF-8")
                                               .as_str();

    // Ocall to normal world for output
    println!("{}", &hello_string);

    let mut sum:u64 = 0;
    let mut vv:Vec<Vec<u8>> = Vec::new();
    let mut onev:Vec<u8>; // 1Mbyte
    let testblocksize:usize = 128 * 1024 * 1024; // 128Mbyte
    let total = 0xB78000000 ; // 46GB - 0.5GB

    for i in 0..total / testblocksize{
        onev = Vec::with_capacity(testblocksize); // 128Mbyte
        for j in 0..testblocksize {
            onev.push(((j as u32) % 256) as u8);
        }
        vv.push(onev);
        sum += testblocksize as u64;
        println!("{}th allocate {} vec sum = {} bytes", i, testblocksize, sum);
    }

    println!("Checking for values in allocated memory");

    for i in 0..total / testblocksize{
        for j in 0..testblocksize {
            if vv[i][j] != ((j as u32) % 256) as u8 {
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            }
        }
    }

    println!("All check success!");

    sgx_status_t::SGX_SUCCESS
}
