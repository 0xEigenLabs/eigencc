#!/bin/bash
set -e
set -x

circuit_name=$1
circom ${circuit_name}.circom --r1cs --wasm --sym

#Prapare phase 1
snarkjs wtns calculate ${circuit_name}.wasm input.json witness.wtns

snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v

#Prapare phase 2
snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v

#Start a new zkey and make a contribution (enter some random text)
snarkjs zkey new ${circuit_name}.r1cs pot12_final.ptau circuit_0000.zkey
snarkjs zkey contribute circuit_0000.zkey circuit_final.zkey --name="1st Contributor Name" -v

snarkjs zkey export verificationkey circuit_final.zkey verification_key.json
snarkjs groth16 prove circuit_final.zkey witness.wtns proof.json public.json
snarkjs groth16 verify verification_key.json public.json proof.json

snarkjs zkey export solidityverifier circuit_final.zkey ../contracts/verifier.sol
