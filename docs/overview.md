# Eigen Network Overview

## EigenCC for Privacy Smart Contract

### Terms
Secret: the records including everything you create in the blockchain network;

### How it work

1. EigenCC issues a key pair, seals the private key on the disk, then distributes the public key to every participants;

2. Client generates an AES key to encrypt it's secret, then encrypt the AES key by public key from step 1;

3. Client makes a transaction with cipher and AES key, and submits the transaction to EVM contract on L2 Geth;

4. The EVM contract on L2 Geth will initialize a context with the encrypted AES key, then there maybe exist multiple `ecall` in one contract method, which all are share 
one context. Finally, all the inputs and outputs from the `ecall`s  will be composed into a DAG with `ecall` as it's nodes and the inputs or outputs as edge.

5. At the end of each contract method, the DAG will be executed in EigenCC. EigenCC decrypts the AES key by the private key from step 1, and then decrepts the cipher by AES key, and executes the DAG, then encrypts the results by AES key;

6. Store the cipher results into the EVM storage.


