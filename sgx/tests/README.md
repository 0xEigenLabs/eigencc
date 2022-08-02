# Tests 

This directory contains all tests in EigenTEE 

## Run Tests

To run all tests with our build system:

```
# cd /path/to/cc/sgx/build
# make sgx-test
```

## Test Coverage

To generate a coverage report for tests, you can configure cmake with `-DCOV=ON`. Then build the platform and run all tests. 
At last, you need to run `make cov` to aggregate coverage results.

```
# mkdir build && cd build
# cmake -DCMAKE_BUILD_TYPE=DEBUG -DCOV=ON -DTEST_MODE=ON ..
# make
# make sgx-test
# make cov
```

## Directory Structure

- `unit`:
  Unit tests are small and more focused, testing one module in isolation at a
  time, and can test private interfaces. This directory contains a test driver to
  test individual units/components or private interfaces. Test cases of unit
  tests are placed along with source code.

