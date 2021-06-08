# EigenCC: Confidential Computation

## Intel SGX

[Intel SGX](https://software.intel.com/content/www/us/en/develop/topics/software-guard-extensions.html) Enhance Your Code and Data Protection

### Compile

```
$ git clone --recursive https://github.com/ieigen/ieigen.git
$ cd cc/sgx 
$ docker run --name fns --net=host -v$(pwd):/app -w /app -it $IMAGE bash
$ mkdir -p build && cd build
$ cmake -DTEST_MODE=ON .. && make
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

## ARM TrustZone on FPGA 
TBD
