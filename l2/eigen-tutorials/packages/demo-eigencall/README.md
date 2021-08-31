# demo-eigencall Tutorial

demo-eigencall is a simple sample example which shows how to call `eigenCall` with all supported operators.

## Config Environment Variables

Set the values shown in `.env-sample` as environmental variables. To copy it into a `.env` file:

```bash
cp .env-sample .env
```

(you'll still need to edit some variables, i.e., `DEVNET_PRIVKEY`, `TEESDK_AUDITOR_BASE_DIR`, `TEESDK_AUDITOR_NAME`, `TEESDK_ENCLAVE_INFO_PATH`)

### Build `teesdk_util`

`teesdk_util` uses dynamic link library `libsdk_c.so`, so firstly we should build `libsdk_c.so`, please see [README.md](../../../../cc/sgx/README.md).

Then enter directory _tools_, run `build.sh` will build an executable file _teesdk_util_.

### Start up `eigen_service`

Please see [README.md](../../../eigen_service/README.md) to know how to start up `eigen_service`.

### Register Tee Key

Just enter directory _tools_, and run `run.sh` will register tee key. Now we can retrieve the public key.

### Run Demo

```bash
yarn run exec
```
