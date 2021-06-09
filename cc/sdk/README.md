## teesdk 
teesdk is the union of sgx client and many other SDKs.

## Usage 

1. build [sgx service](../sgx), and copy the `release/lib` to sdk;

2. build teesdk;
```
./build.sh
```
output files are in build directory

3. import the library above in Golang project
