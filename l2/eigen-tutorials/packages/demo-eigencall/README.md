# demo-eigencall Tutorial

demo-eigencall is a simple sample example which shows how to call `eigenCall` with all supported operators.

## Config Environment Variables

Set the values shown in `.env-sample` as environmental variables. To copy it into a `.env` file:

```bash
cp .env-sample .env
```

(you'll still need to edit some variables, i.e., `DEVNET_PRIVKEY`, `L1RPC`, `L2RPC`, `PKCS`)

### Start up `eigen_service`

Please see [README.md](https://github.com/ieigen/ieigen/blob/main/l2/eigen_service/README.md) to know how to start up `eigen_service`.


### Build

```
yarn && yarn build
```

### Register [PKCS](https://github.com/ieigen/ieigen/blob/main/l2/eigen_service/README.md#pkcs)

The PKCS is public key cache service. All the private inflow to EigenCC have to be encrypted by the public key in PKCS, which 
is registered by running ```yarn run pkcs```.

### Run Demo

Here 2 demos are provided, one is custom token,

```bash
yarn run deploy
```
and the other is confidential ERC20.
```bash
yarn run exec
```
