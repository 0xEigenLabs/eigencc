# EigenRollup

EigenRoll provides a privacy-preserving smart contract on mixed layer 2 Rollup protocols of current main public blockchain, such as Ethereum. EigenRollup initiailly implements the protocal by refering to Arbitrum.   

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
