// SPDX-License-Identifier: GPL-3.0
pragma solidity >0.4.20;
 
contract Hello {
 
    string name;
    address id;
 
    constructor() public {
        name = 'Hello world!';
    }
 
    function hello() view public returns (address, string memory) {
        bytes32 aa = ecall("2121");
        return (msg.sender, name);
    }
}
