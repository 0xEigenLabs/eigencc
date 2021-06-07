# Add a new instruction in AVM

[TOC]

## [WIP] Add New Instructions for private computing in AVM

1. Clone repo
```bash
git clone --recursive https://github.com/offchainlabs/arbitrum.git

# Modify avm-cpp
cd arbitrum

git checkout 4f1a02688

git apply ../add-avm-cpp.diff

# Modify arb-os
cd packages/arb-os

git checkout 3c28bc5a6


git apply ../../../arb-os.diff
```

2. Then depoly L1 and L2

```bash
# In `arbitrum' directory
yarn

yarn build

# Build and depoloy L1
yarn docker:build:geth

yarn docker:geth

# Configure L2
yarn demo:initialize

# Fire up L2 and deploy the validator (and avm-cpp will be build in this stage)
yarn demo:deploy
```

3. Deploy contract by `truffle`

```bash
# In `ieigen/l2/new_avm_instr' directory

# Add package requriements
yarn add --dev arb-ethers-web3-bridge
yarn add --dev @truffle/hdwallet-provider

# Deploy the contract
truffle migrate --reset --network arbitrum

# Call the contract
truffle console --network arbitrum


# truffle(arbitrum)> Hello.deployed().then(instance => contract = instance)
# contract.hello()
```
