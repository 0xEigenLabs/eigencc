#!/bin/bash

export GO111MODULE=on

rm -rf build
mkdir -p build
go build -buildmode=plugin -o=./build/opt_teesdk.so.0.0.1 ./sgx/optimism
