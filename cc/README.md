# EigenCC: Confidential Computation

## Intel SGX

[Intel SGX](https://software.intel.com/content/www/us/en/develop/topics/software-guard-extensions.html) Enhance Your Code and Data Protection

### Requirements
Rust SGX SDK: 1.1.3

Rust Version: rustup default nightly-2020-10-25

### Compile

```
$ git clone --recursive https://github.com/ieigen/ieigen.git
$ cd cc/sgx 
$ docker run --name fns --net=host -v$(pwd):/app -w /app -it $IMAGE bash
$ rustup default nightly-2020-10-25
$ mkdir -p build && cd build
$ cmake .. && make # or use SIM mode: cmake .. -DSGX_SIM_MODE=on && make 
```

Build $IMAGE image by [Dockerfile](./sgx/dcap/Dockerfile)

### Run

use EPID:
```
$ cd /app/release/services
$ export IAS_SPID=xxxx
$ export IAS_KEY=xxx
$ cd /teaclave/release/services
$ ./fns
```
open another terminal,
```
$ cd /teaclave/release/examples
$ ./quickstart echo -m 'Hello' -e enclave_info.toml
[+] Invoke echo function
Hello, Eigen
```

### Develop an new confidential service
[EigenCC Privacy Operators](../docs/operators.md)

## ARM TrustZone on FPGA 
TBD
