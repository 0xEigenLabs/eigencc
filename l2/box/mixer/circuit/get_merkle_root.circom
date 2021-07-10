include "../../circomlib/circuits/mimc.circom";

template GetMerkleRoot(k){
// k is depth of tree

    signal input leaf;
    signal input paths2_root[k];
    signal input paths2_root_pos[k];

    signal output out;

    // hash of first two entries in tx Merkle proof
    component merkle_root[k];
    merkle_root[0] = MiMC7(91);
    merkle_root[0].x_in <== paths2_root[0] - paths2_root_pos[0]* (paths2_root[0] - leaf);
    merkle_root[0].k <== leaf - paths2_root_pos[0]* (leaf - paths2_root[0]);

    // hash of all other entries in tx Merkle proof
    for (var v = 1; v < k; v++){
        merkle_root[v] = MiMC7(91);
        merkle_root[v].x_in <== paths2_root[v] - paths2_root_pos[v]* (paths2_root[v] - merkle_root[v-1].out);
        merkle_root[v].k<== merkle_root[v-1].out - paths2_root_pos[v]* (merkle_root[v-1].out - paths2_root[v]);
    }

    // output computed Merkle root
    out <== merkle_root[k-1].out;

}
