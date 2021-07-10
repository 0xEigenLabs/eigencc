const HDWalletProvider = require('@truffle/hdwallet-provider');

const BN = require('bn.js');
const fs = require("fs")
var contract = require("truffle-contract");
var MixerData = require("../build/contracts/Mixer.json");
var Mixer = contract(MixerData);

var provider = new HDWalletProvider("total mail avocado lava vast trade gap police vibrant lounge disorder shine", "http://127.0.0.1:7545");
Mixer.setProvider(provider);
var web3 = Mixer.web3;

var MixerAddress = "0x5098d488225dF93840cbbb176Bb05DF4c39C16b7";

const argv = process.argv
if (argv.length < 3) {
    console.log('please specify the file path to be processed')
    return
}
MixerAddress = argv[2];
console.log("Mixer", MixerAddress)

var MixerInstance;

var FromAddress = "0x4F5FD0eA6724DfBf825714c2742A37E0c0d6D7d9";
var Amount = web3.utils.toWei('0.01', 'ether');

async function getInstance() {
    MixerInstance = await
        Mixer.at(MixerAddress);
}

// deposit
// 0,1,2,3
// 11730251359286723731141466095709901450170369094578288842486979042586033922425,
// 12240136457100152345096610842396488822128317434453048685489891202497829360467,
// 20808841395409656332564552932284796001294721646723037196107424963391316010609,
// 10513607674170245577899825752483841247286555366379776940083295721103562343571

async function deposit(cmt){
	await getInstance();

	await MixerInstance.deposit(cmt,{
		from: FromAddress,
		value: Amount,
		gas: 3000000,
		gasPrice: "20000000000"
	});
    console.log("deposit done")
}

deposit("11730251359286723731141466095709901450170369094578288842486979042586033922425")

// getMerkleProof
async function getMerkleProof(leaf_index) {
    await getInstance();
    let proof = await MixerInstance.getMerkleProof.call(leaf_index);
    console.info(proof);

    for (let i=0 ;i< proof[0].length;i++){
    	let t =  new BN(proof[0][i]);
    	console.info(t.toString())
    }

    for (let i=0 ;i< proof[1].length;i++){
    	let t =  new BN(proof[1][i]);
    	console.info(t.toString())
    }
    console.log("getMerkleProof done")
}

getMerkleProof(0)

// root
// 8749535955750417528732286737236417644637614278119434265686374177373578555555
async function getRoot() {
	await getInstance();

	let root =  new BN(await MixerInstance.getRoot.call());

    console.log(root.toString(), "getRoot done")
}

getRoot()

// withdraw
// get the first parameter from `snarkjs generatecall`
async function withdraw(){
    await getInstance();
    await MixerInstance.withdraw(
        ["0x2c5bb101cb5700fdeb517e7bd4bf3ee9019fda4237c92cabc5578cbec9b2689b", "0x1950a5cd487fff9aec18b78472b1e5cfeac297e16648550c9a40f80398d2ae69"],[["0x0f6148c49e0e3fd61f9d65f617f8fae7824f2fef17bcd3729d0787f31ab12888", "0x1cee9391f5d49df300fd5879998161274814ba3f53da76ea76a450ec0441dc3d"],["0x22b1609907c942c54b67e4c1f5d49f2660bb65f2b61c31f3f5dcb0671dbc20dc", "0x206d71186b726be4fb8cd9be0ba7a019758024c22ef1e684b214744c8d31dd5a"]],["0x1b1acf3c8bc9ce8e5f20de49cfa89cc645bb6beadcfeb17ef7b77dcf35931b96", "0x0315a2ca11393eaad085773938587dc9e97c780882e2cd119c768e16e2ebd96b"],["0x2ec2d13597576e6e9a28d337af768c614a0b892a38aece30dd4df4b1138edf35","0x11ef8fc9e658c40fa4a8ae1d40e81084befc8a507f560bb0f2c33bb14cca567d"],
        {
            from: FromAddress,
            gas: 3000000,
            gasPrice: "20000000000"
        }
    );
    console.log("withdraw done")
}

withdraw()
