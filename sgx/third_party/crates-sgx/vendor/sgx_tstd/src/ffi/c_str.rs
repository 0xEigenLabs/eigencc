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

pub use sgx_trts::c_str::*;

use crate::error::Error;
use crate::io;

impl Error for NulError {
    fn description(&self) -> &str {
        "nul byte found in data"
    }
}

impl From<NulError> for io::Error {
    /// Converts a [`NulError`] into a [`io::Error`].
    ///
    /// [`NulError`]: ../ffi/struct.NulError.html
    /// [`io::Error`]: ../io/struct.Error.html
    fn from(_: NulError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, "data provided contains a nul byte")
    }
}

impl Error for FromBytesWithNulError {
    fn description(&self) -> &str {
        self.__description()
    }
}

impl Error for IntoStringError {
    fn description(&self) -> &str {
        self.__description()
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.__source())
    }
}
