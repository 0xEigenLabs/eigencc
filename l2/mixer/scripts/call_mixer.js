const HDWalletProvider = require('@truffle/hdwallet-provider');
require("dotenv").config()
const BN = require('bn.js');
const fs = require("fs")
var contract = require("truffle-contract");
var MixerData = require("../build/contracts/Mixer.json");
var proof = require("../circuit/proof.json")
var Mixer = contract(MixerData);

var provider = new HDWalletProvider(process.env.MNEMONIC, process.env.RPC);
Mixer.setProvider(provider);
var web3 = Mixer.web3;

async function getFromAddr() {
  let acc = await web3.eth.getAccounts()
  return acc[0]
}

var MixerInstance;

var Amount = web3.utils.toWei('0.01', 'ether');

async function getInstance() {
  MixerInstance = await
    Mixer.at(process.env.MIXER_ADDR);
}

// deposit
// 0,1,2,3
async function deposit(cmt){
  await getInstance();

  var tx = await MixerInstance.deposit(cmt,{
    from: await getFromAddr(),
    value: Amount,
    gas: 3000000,
    gasPrice: "20"
  });
  console.log("deposit done, ", tx.tx)
}

// getMerkleProof
async function getMerkleProof(leaf_index) {
  await getInstance();
  let proof = await MixerInstance.getMerkleProof.call(leaf_index);
  console.info("proof", proof);

  for (let i=0 ;i< proof[0].length;i++){
    let t =  new BN(proof[0][i]);
    console.info("0", t.toString())
  }

  for (let i=0 ;i< proof[1].length;i++){
    let t =  new BN(proof[1][i]);
    console.info("1", t.toString())
  }
  console.log("getMerkleProof done")
}

// root
async function getRoot() {
  await getInstance();
  let root =  new BN(await MixerInstance.getRoot.call());
  console.log("root:", root.toString())
  return root
}


// withdraw
// get the first parameter from `snarkjs generatecall`
async function withdraw(){
  await getInstance();
  const proof = require("../circuit/proof.json")
  const public = require("../circuit/public.json")
  const root = await getRoot()
  const tx = await MixerInstance.withdraw(
    // TODO
    [proof.pi_a[0], proof.pi_a[1]],
    [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]],
    [proof.pi_c[0], proof.pi_c[1]],
    public,
    root,
    {
      from: await getFromAddr(),
      gas: 8000000,
      gasPrice: 100
    }
  );
  console.log("withdraw done, ", tx.tx)
}

const wait = async (i) => {
    setTimeout(function() { console.log("Waiting") }, i);
}

const cmt = require("../circuit/cmt.json")

const argv = process.argv

if (argv[2] == "d") {
  console.log("d")
  deposit(cmt)
    .then(() => {
      getMerkleProof(0)
      getRoot()
    })

} else {
  console.log("w")
  withdraw()
}

