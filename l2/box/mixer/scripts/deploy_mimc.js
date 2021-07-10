const ganache = require("ganache-cli");
const Web3 = require("web3");
const chai = require("chai");
const mimcGenContract = require("../../circomlib/src/mimc_gencontract.js");
const mimcjs = require("../../circomlib/src/mimc7.js");
const HDWalletProvider = require('@truffle/hdwallet-provider');

const assert = chai.assert;
const log = (msg) => { if (process.env.MOCHA_VERBOSE) console.log(msg); };

const SEED = "mimc";

describe("MiMC Smart contract test", function () {
    let testrpc;
    let web3;
    let mimc;
    let accounts;

    this.timeout(100000);

    before(async () => {
        web3 = new Web3(new HDWalletProvider("total mail avocado lava vast trade gap police vibrant lounge disorder shine",
            "http://127.0.0.1:7545"), null, {transactionConfirmationBlocks: 1});
        accounts = await web3.eth.getAccounts();
    });

    it("Should deploy the contract", async () => {
        const C = new web3.eth.Contract(mimcGenContract.abi);

        mimc = await C.deploy({
            data: mimcGenContract.createCode(SEED, 91),
            arguments: []
        }).send({
            gas: 1500000,
            gasPrice: '30000000000000',
            from: accounts[0]
        }).on("error", (error) => {
            console.log("ERROR: "+error);
        });
        console.log("mimc address: ", await mimc.options.address)
    });

    it("Shold calculate the mimic correctly", async () => {
        const res = await mimc.methods.MiMCpe7(1,1).call();
        const res2 = await mimcjs.hash(1,1,91);
        console.info(res.toString())
        assert.equal(res.toString(), res2.toString());
    });
});

