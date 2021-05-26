# EigenCC: Confidential Computation

## Intel SGX

[Intel SGX](https://software.intel.com/content/www/us/en/develop/topics/software-guard-extensions.html) Enhance Your Code and Data Protection

### Compile

```
$ cd cc/sgx 
$ docker run --name fns --net=host -v$(pwd):/app -w /app -it $IMAGE bash
# mkdir -p build && cd build
# cmake -DTEST_MODE=ON .. && make
```

Build $IMAGE image by [Dockerfile](./sgx/dcap/Dockerfile)

### Run

use EPID:
```
# cd /app/release/services
# export IAS_SPID=xxxx
# export IAS_KEY=xxx
# ./fns
```
use DCAP: 

```
# cd release/dcap && ./eigen_dcap_server
# eigen_tools 
TBD
```


## ARM TrustZone on FPGA 

TBD
