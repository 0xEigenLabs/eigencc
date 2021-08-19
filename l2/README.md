# EigenRollup

EigenRollup provides a privacy-preserving smart contract on mixed layer 2 Rollup protocols of current main public blockchain, such as Ethereum. EigenRollup initiailly implements the protocol on Arbitrum.

## [WIP] Add New Instructions for private computing

1. To use Arbitrum:

```bash
git clone -b dev https://github.com/ieigen/arbitrum
cd arbitrum

git submodule update --init --recursive

yarn
yarn build
```

2. Running on Local Blockchain

To run Arbitrum locally, you need several things:

  - Launching a Local Ethereum Blockchain (the L1)

  ```bash
  yarn docker:build:geth

  # Set DEVNET_PRIVKEY, for example:
  export DEVNET_PRIVKEY="0x2323232323232323232323232323232323232323232323232323232323232323"
  yarn docker:geth
  ```

  - Configuring your local Arbitrum chain (the L2)

  ```bash
  # If in another terminal, we should set DEVNET_PRIVKEY again with the same value as before
  
  yarn demo:initialize
  ```

  - Firing up the Arbitrum L2 and Deploying your validator(s)

  ```bash
  yarn demo:deploy
  ```

3. Run tutorial `demo-eigencall`

```bash
cd eigen-tutorials
# Install some dependencies
yarn

# Run tutorial
cd packages/demo-iegencall

yarn run exec
```
