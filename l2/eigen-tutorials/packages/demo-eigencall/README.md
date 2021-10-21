# demo-eigencall Tutorial

demo-eigencall is a simple sample example which shows how to call `eigenCall` with all supported operators.

## Config Environment Variables

Set the values shown in `.env-sample` as environmental variables. To copy it into a `.env` file:

```bash
cp .env-sample .env
```

(you'll still need to edit some variables, i.e., `DEVNET_PRIVKEY`, `TEESDK_AUDITOR_BASE_DIR`, `TEESDK_AUDITOR_NAME`, `TEESDK_ENCLAVE_INFO_PATH`)

### Start up `eigen_service`

Please see [README.md](https://github.com/ieigen/ieigen/blob/main/l2/eigen_service/README.md) to know how to start up `eigen_service`.

### Build `teesdk_util`

`teesdk_util` uses dynamic link library `libsdk_c.so`, so firstly we should build `libsdk_c.so`, please see [README.md](https://github.com/ieigen/ieigen/blob/main/cc/README.md).

build it and register the public key to PKCS by
```
yarn run docker:reg
```

### Run Demo

```bash
yarn run exec
```
