###  Requirement

- circom
	- 0.5.45
- python
	- 3.6.12
- nodejs
	- v12.0.0
- solidity
	- v0.5.16
- truffle
    - v5.3.14

hasher：mimc7

### Steps

- compose circuits
	- mixer.circom
	- get_merkle_root.circom

- compose contracts
	- mixer
	- Merkle

### Circuits


#### generate public input，Private input

```
$ yarn generate
```

#### Compile

```
$ cd circuit;  ./run.sh mixer
```
Wait until you are asked to type in the random text, and input the same secret twice!!

#### Test

```
$ yarn deploy_mimc
$ ### find the contract address from geth console, and change the mimc address in migrations/2_deploy_contracts.js
$ yarn call_mimc ${mimc address}

$ truffle migrate --reset
$ yarn call_mixer ${mixer address}
```

### Reference
1. https://keen-noyce-c29dfa.netlify.com/#2
2. https://blog.iden3.io/first-zk-proof.html
