var Web3 = require("web3");
var web3 = new Web3(new Web3.providers.HttpProvider('http://localhost:7545'));

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

const argv = process.argv
if (argv.length < 3) {
    console.log('invalid argument')
    return
}
MimcAddress = argv[2];
var MyContract = new web3.eth.Contract(abi, MimcAddress);
MyContract.methods.MiMCpe7(1,1).call()
.then(console.log);


