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

  - Launching a Local Ethereum Blockchain (the L1)

  ```bash
  yarn docker:build:geth
  yarn docker:geth
  ```

  - Configuring your local Arbitrum chain (the L2)

  ```bash
  yarn demo:initialize
  ```

  - Firing up the Arbitrum L2 and Deploying your validator(s)

  ```bash
  yarn demo:deploy
  ```

3. Deploy contract by truffle in `new_instr`

```bash
# Install some dependencies
npm install @truffle/hdwallet-provider

# Deploy the contracts
truffle migrate --reset --network arbitrum

# Test our contracts
truffle console --network arbitrum
```
