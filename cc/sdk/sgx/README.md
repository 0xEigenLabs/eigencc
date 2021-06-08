## teesdk 
A EigenCC SDK by Golang as a wrapper of the C SDK

## Usage 
1. compile [EigenCC](../../sgx), and update the dylib [lib/libeigentee_sdk_c.so](./lib/libeigentee_sdk_c.so)

2. start the fns service;

3. run the unit test  
```
go test -v ./... -mod=vendor
```
or your program.
