var Web3 = require("web3");
require("dotenv").config()
var web3 = new Web3(new Web3.providers.HttpProvider(process.env.RPC));

var abi = [
    {
        "constant": true,
        "inputs": [
            {
                "name": "in_x",
                "type": "uint256"
            },
            {
                "name": "in_k",
                "type": "uint256"
            }
        ],
        "name": "MiMCpe7",
        "outputs": [
            {
                "name": "out_x",
                "type": "uint256"
            }
        ],
        "payable": false,
        "stateMutability": "pure",
        "type": "function"
    }
];

mimcAddress = process.env.MIMC_ADDR || process.exit(-1);
var MyContract = new web3.eth.Contract(abi, mimcAddress);
//TODO edit leaf and depth
MyContract.methods.MiMCpe7(1,1).call()
.then(console.log);
