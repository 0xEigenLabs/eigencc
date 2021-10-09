// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2020, Offchain Labs, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

pragma solidity ^0.6.11;

import "../arbitrum/IArbToken.sol";
import "../libraries/aeERC20.sol";
import "../arbitrum/ArbTokenBridge.sol";
import "../../arbos/builtin/ArbSys.sol";

import "./RLPEncode.sol";
import "solidity-rlp/contracts/RLPReader.sol";

contract TestArbCustomToken is aeERC20, IArbToken {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for bytes;

    ArbTokenBridge public bridge;
    address public override l1Address;

    // Mapping from token ID to approved address
    mapping(address => bytes) private _cipher_balances;

    modifier onlyBridge() {
        require(msg.sender == address(bridge), "ONLY_BRIDGE");
        _;
    }

    constructor(address _bridge, address _l1Address) public {
        bridge = ArbTokenBridge(_bridge);
        l1Address = _l1Address;
        aeERC20.initialize("TestCustomToken", "CARB", uint8(18));
    }

    function someWackyCustomStuff() public {}

    function cipherBalanceOf(address account) public view virtual returns (bytes memory) {
        return _cipher_balances[account];
    }

    function uint256_to_string(uint256 _i) internal pure returns (string memory str) {
        if (_i == 0) {
            return "0";
        }
        uint256 j = _i;
        uint256 length;
        while (j != 0) {
            length++;
            j /= 10;
        }
        bytes memory bstr = new bytes(length);
        uint256 k = length;
        j = _i;
        while (j != 0) {
            bstr[--k] = bytes1(uint8(48 + (j % 10)));
            j /= 10;
        }
        str = string(bstr);
    }

    function copy_bytes(bytes memory _bytes) private pure returns (bytes memory) {
        bytes memory copy = new bytes(_bytes.length);
        uint256 max = _bytes.length + 31;
        for (uint256 i = 32; i <= max; i += 32) {
            assembly {
                mstore(add(copy, i), mload(add(_bytes, i)))
            }
        }
        return copy;
    }

    function bridgeMint(address account, uint256 amount) external override onlyBridge {
        _mint(account, amount);
        bytes[] memory list;

        list = new bytes[](4);

        list[0] = RLPEncode.encodeString("encrypt");
        list[1] = RLPEncode.encodeString(uint256_to_string(amount));
        list[2] = RLPEncode.encodeString("");
        list[3] = RLPEncode.encodeString("");
        bytes memory encrypt_bytes = RLPEncode.encodeList(list);

        bytes memory rlp_encoded_result = ArbSys(address(100)).eigenCall(encrypt_bytes);

        bytes memory cipher_base64 = rlp_encoded_result.toRlpItem().toBytes();
        _cipher_balances[account] = copy_bytes(cipher_base64);
    }

    function bridgeBurn(address account, uint256 amount) external override onlyBridge {
        _burn(account, amount);

        bytes[] memory list;

        list = new bytes[](4);
        bytes memory cipher_base64_balance = _cipher_balances[account];

        list[0] = RLPEncode.encodeString("sub_cipher_plain");
        list[1] = RLPEncode.encodeBytes(cipher_base64_balance);
        list[2] = RLPEncode.encodeString(uint256_to_string(amount));
        list[3] = RLPEncode.encodeString("");
        bytes memory encrypt_bytes = RLPEncode.encodeList(list);

        bytes memory rlp_encoded_result = ArbSys(address(100)).eigenCall(encrypt_bytes);
        bytes memory cipher_base64 = rlp_encoded_result.toRlpItem().toBytes();
        _cipher_balances[account] = copy_bytes(cipher_base64);
    }

    function withdraw(address destination, uint256 amount) external override {
        bridge.withdraw(l1Address, msg.sender, destination, amount);
    }
}
