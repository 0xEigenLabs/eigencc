### Mixer

A coin mixer implementation based on ZKP for privacy-preserving DeFi and DAO. NOTE that it's not production ready.

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

### Components

- Circuits
	- mixer.circom
	- get_merkle_root.circom

-  Contracts
	- Mixer
	- Merkle

### Compile


#### generate public input，Private input

```
$ cd ..
$ git clone https://github.com/iden3/circomlib.git
$ cd circomlib && yarn && cd ../mixer
$ # edit .env and setup SECRET and LEAF_NUM
$ cp .env.sample .env
$ yarn generate
```

#### Compile circuits

```
$ cd circuit && ./run.sh mixer
```
Wait until you are asked to type in the secret phase, twice!!

#### Deploy contracts

1. deploy mimc

```
$ yarn deploy_mimc
$ export MIMC_ADDR=${mimc address from above deployment}
$ yarn call_mimc
```

2. deploy mixer
```
$ truffle migrate --reset
$ export MIXER_ADDR=${mixer address from above}
$ #generate the first parameter of withdraw and replace it in script/call_mixer.js.
$ cd circuit && snarkjs generatecall
$ yarn call_mixer d
$ yarn call_mixer w

```

### How it work

Mixer is built on `Groth16` and `Merkle Tree`.

* Groth16

Groth16 is one of the most famous zksnark proving schemes (in addition to pghr13, gm17, etc.). 
Compared with the previous proof protocol, groth16 has the characteristics of small proof data 
(only three proof data) and fast verification speed (only one equation needs to be verified). 
At present, groth16 has been widely used in many projects, such as zcash, filecoin, etc.
Groth16 is a zero knowledge proof protocol proposed by Daniel Jens growth in his paper 
"on the size of pairing based non interactive arguments" published in 2016.
The name of the general algorithm is composed of the first letter of the author’s surname 
and the year.

More details are presented [here](https://eprint.iacr.org/2016/260.pdf).

* MIMC
MiMC is a block cipher and hash function family designed specifically for SNARK applications. 
The low multiplicative complexity of MiMC over prime fields makes it suitable for ZK-SNARK 
applications such as ZCash.
More details are [here](https://byt3bit.github.io/primesym/mimc/).

* `yarn generate`
This operation produces 4 files in circuit directory:
>* input.json :  secret for mixer to generate witness, a sample is as below: 
```
{
    "root": "6006452839415899035733807029325942815929888768074345937414569668512067894100",
    "nullifierHash": "3701224944747537563701225775873437347582519438989321326160774689502152321319",
    "secret": "10",
    "paths2_root": [
        3174904703,
        1831855034,
        2927866351,
        3904382600,
        4026780824,
        2259814112,
        3460561431,
        3054720229
    ],
    "paths2_root_pos": [
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1
    ]
}
```
where `root` is the merkle root, and `nullifierHash` is nullifier to check whether the commitment has been withdrawed. The secret is used to generate the commitment by hash function in binary format, paths2_root        is the salt for each non-leaf node to compute it's hash.  And paths2_root_pos is 0 or 1, used as a sign function to choose whether paths2_root as `xIn` and previous path2_root as `k`, and vice versa. The circom code shown as below:

```
merkle_root[v].x_in <== paths2_root[v] - paths2_root_pos[v] * (paths2_root[v] - merkle_root[v-1].out);
merkle_root[v].k<== merkle_root[v-1].out - paths2_root_pos[v]* (merkle_root[v-1].out - paths2_root[v]);
```

>* public.json: includes nullifierHash and root.
>* cmt.json: the parameter of deposit

* `./run.sh mixer`

Here we use `Groth16` and curve bn128 to generate verification key and proof key.  More details are presented in reference 1.  One point should be mentioned is [powersoftau](https://eprint.iacr.org/2017/1050), which adopts MPC to generate verifiable Random Beacon as CRS,  to secure their secret randomness throughout the duration of the protocol.

* `yarn deploy_mimc`
Deploy MiMC contract.

* `yarn call_mimc`
Test if MiMC contract deployed successfully

* `truffle migrate --reset`
Deploy Mixer, which is derivative of Merkle Tree and Verifier.

* `yarn call_mixer`
>* deposit(cmt, amount): load the parameter from `circuit/cmt.json`, and deposit amount into Mixer.
>* withdraw(a, b, c, input): a, b, c can be obtained by `snarkjs generatecall`, and input is from `circuit/public.json` , and this method refund the monery from Mixer to `msg.from`
>* forward(a, b, c, input, cmt): forward current account's asset to another anonymous account.

### TODO
* fix the circuits to verify the new root
* tx origin check before deposit

### Reference
1. https://keen-noyce-c29dfa.netlify.com/#2
2. https://blog.iden3.io/first-zk-proof.html
