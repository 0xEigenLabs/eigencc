# EigenCC: Confidential Computation

## Intel SGX

[Intel SGX](https://software.intel.com/content/www/us/en/develop/topics/software-guard-extensions.html) Enhance Your Code and Data Protection

### Requirements
Rust SGX SDK: 1.1.3

Rust Version: rustup default nightly-2020-10-25

### Compile

```
$ git clone --recursive https://github.com/ieigen/ieigen.git  # if clone failed, use `git submodule update --init` to pull submodules 
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
$ cd /app/release/services
$ #the next step can be skipped if you use SIM mode
$ LD_LIBRARY_PATH="/opt/intel/sgx-aesm-service/aesm:$LD_LIBRARY_PATH" /opt/intel/sgx-aesm-service/aesm/aesm_service
$ ./fns
```
open another terminal,
```
$ cd /app/release/examples
$ ./quickstart echo -m 'Hello' -e enclave_info.toml
[+] Invoke echo function
Hello, Eigen
```

#### Run GBDT training

```
cd /app/release/examples
./quickstart echo -e enclave_info.toml  -m Hello \
    -t ../../../../data/agaricus-lepiota/test.txt \
    -r ../../../../data/agaricus-lepiota/train.txt
```
then you can see the AUC of training from terminal of fns.

### Develop an new confidential service
[EigenCC Privacy Operators](../docs/operators.md)

## ARM TrustZone on FPGA 
TBD
