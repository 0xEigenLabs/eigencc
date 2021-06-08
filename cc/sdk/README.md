## teesdk 
teesdk is the union of sgx client and many other SDKs.

## Usage 

1. run the unit test  
```
go test -v ./...
```

2. build teesdk
```
./build.sh
```
output files are in build directory

3. use the `opt_teesdk.so.0.0.1` from build directory in optimism external interface.
