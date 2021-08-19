pragma solidity ^0.7.0;

import "arb-shared-dependencies/contracts/ArbSys.sol";

contract EigencallDemo {
	event Returns(bytes returnValue);
	// call eigenCall
	function call_eigenCall(bytes calldata input) public returns (bytes memory) {
  		bytes memory output = ArbSys(address(100)).eigenCall(input);
		emit Returns(output);
		return output;
	}
}