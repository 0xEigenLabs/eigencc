include "./get_merkle_root.circom";
include "../../circomlib/circuits/mimc.circom";
include "../../circomlib/circuits/bitify.circom";

template Withdraw(k){
	// public input
	signal input root;
	signal input nullifierHash;

	// private input
	signal private input secret;
	
	signal private input paths2_root[k];
    signal private input paths2_root_pos[k];

	// root constrain
	component leaf = MiMC7(91);
	leaf.x_in <== secret;
	leaf.k <== 0;

    component computed_root = GetMerkleRoot(k);
    computed_root.leaf <== leaf.out;

    for (var w = 0; w < k; w++){
        computed_root.paths2_root[w] <== paths2_root[w];
        computed_root.paths2_root_pos[w] <== paths2_root_pos[w];
    }
    root === computed_root.out;

	// nullifier constrain
	component cmt_index = Bits2Num(k);
	for (var i =0 ;i < k ; i++){
		cmt_index.in[i] <== paths2_root_pos[i];
	}

	component nullifier = MiMC7(91);
	nullifier.x_in <== cmt_index.out;
	nullifier.k <== secret;

	nullifierHash === nullifier.out;
	
}

component main = Withdraw(8);
