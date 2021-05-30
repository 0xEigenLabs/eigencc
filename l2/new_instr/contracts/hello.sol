// SPDX-License-Identifier: GPL-3.0
pragma solidity >0.4.20;
 
contract Hello {
 
    string name;
    address id;
 
    constructor() public {
        name = 'Hello world!';
    }
 
    function hello() public returns (address, string memory) {
        bytes32 aa = ecall("2121");
        log1('new_inst', aa);
        return (msg.sender, name);
    }
}
