# EigenLedger

We launch our network on [Layer 2 of Ethereum](https://github.com/ethereum-optimism/optimism), and extend the EVM and [solc](https://github.com/ieigen/solidity) to support privacy computing operators.

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

  1. Launching a Local Ethereum Blockchain (the L1)
	
  ```bash
  yarn docker:build:geth
  yarn docker:geth
  ```

  2. Configuring your local Arbitrum chain (the L2)

  ```bash
  yarn demo:initialize
  ```

  3. Firing up the Arbitrum L2 and Deploying your validator(s)

  ```bash
  yarn demo:deploy
  ```

3. Deploy contract by truffle in `new_instr`
