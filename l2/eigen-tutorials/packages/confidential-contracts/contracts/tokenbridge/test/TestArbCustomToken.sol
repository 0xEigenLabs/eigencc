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

import "@openzeppelin/contracts/utils/Strings.sol";

import "../arbitrum/IArbToken.sol";
import "../libraries/aeERC20.sol";
import "../arbitrum/ArbTokenBridge.sol";

import "../../arbos/builtin/ArbSys.sol";
import "./RLPEncode.sol";
import "solidity-rlp/contracts/RLPReader.sol";

contract TestArbCustomToken is aeERC20, IArbToken {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for bytes;
    using Strings for uint256;

    ArbTokenBridge public bridge;
    address public override l1Address;

    // Mapping from token ID to approved address
    mapping(address => bytes) private _cipher_balances;

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event TransferCipher(address indexed from, address indexed to, bytes value);

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

    function bridgeMint(address account, uint256 amount) external override onlyBridge {
        _mint(account, amount);

        bytes memory cipher_base64 = encrypt(amount);
        _cipher_balances[account] = copy_bytes(cipher_base64);
    }

    function bridgeBurn(address account, uint256 amount) external override onlyBridge {
        _burn(account, amount);

        bytes memory cipher_base64_balance = _cipher_balances[account];
        bytes memory cipher_base64 = subCipherPlain(cipher_base64_balance, amount);
        _cipher_balances[account] = copy_bytes(cipher_base64);
    }

    function withdraw(address destination, uint256 amount) external override {
        bridge.withdraw(l1Address, msg.sender, destination, amount);
    }

    function cipherTransfer(address recipient, bytes memory cipher_amount)
        public
        virtual
        returns (bool)
    {
        require(_msgSender() != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        bytes[] memory list;
        list = new bytes[](4);

        bytes memory sender_cipher_base64_balance = _cipher_balances[_msgSender()];
        bytes memory sender_cipher_base64 = subCipherCipher(
            sender_cipher_base64_balance,
            cipher_amount
        );
        _cipher_balances[_msgSender()] = copy_bytes(sender_cipher_base64);

        bytes memory recipient_cipher_base64_balance = _cipher_balances[recipient];
        bytes memory recipient_cipher_base64 = addCipherCipher(
            recipient_cipher_base64_balance,
            cipher_amount
        );
        _cipher_balances[recipient] = copy_bytes(recipient_cipher_base64);
        emit TransferCipher(_msgSender(), recipient, cipher_amount);
        return true;
    }

    function cipherTransferFrom(
        address sender,
        address recipient,
        bytes memory cipher_amount
    ) public virtual returns (bool) {
        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        bytes[] memory list;
        list = new bytes[](4);

        bytes memory sender_cipher_base64_balance = _cipher_balances[sender];
        bytes memory sender_cipher_base64 = subCipherCipher(sender_cipher_base64_balance, cipher_amount);
        _cipher_balances[sender] = copy_bytes(sender_cipher_base64);

        bytes memory recipient_cipher_base64_balance = _cipher_balances[recipient];
        bytes memory recipient_cipher_base64 = addCipherCipher(
            recipient_cipher_base64_balance,
            cipher_amount
        );
        _cipher_balances[recipient] = copy_bytes(recipient_cipher_base64);
        emit TransferCipher(sender, recipient, bytes(cipher_amount));

        return true;
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);

        require(_msgSender() != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        bytes[] memory list;
        list = new bytes[](4);

        bytes memory sender_cipher_base64_balance = _cipher_balances[_msgSender()];
        bytes memory sender_cipher_base64 = subCipherPlain(sender_cipher_base64_balance, amount);
        _cipher_balances[_msgSender()] = copy_bytes(sender_cipher_base64);

        bytes memory recipient_cipher_base64_balance = _cipher_balances[recipient];
        bytes memory recipient_cipher_base64 = addCipherPlain(
            recipient_cipher_base64_balance,
            amount
        );
        _cipher_balances[recipient] = copy_bytes(recipient_cipher_base64);
        emit TransferCipher(_msgSender(), recipient, bytes(amount.toString()));
        return true;
    }

    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) public virtual override returns (bool) {
        _transfer(sender, recipient, amount);

        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        bytes[] memory list;
        list = new bytes[](4);

        bytes memory sender_cipher_base64_balance = _cipher_balances[sender];
        bytes memory sender_cipher_base64 = subCipherPlain(sender_cipher_base64_balance, amount);
        _cipher_balances[sender] = copy_bytes(sender_cipher_base64);

        bytes memory recipient_cipher_base64_balance = _cipher_balances[recipient];
        bytes memory recipient_cipher_base64 = addCipherPlain(
            recipient_cipher_base64_balance,
            amount
        );
        _cipher_balances[recipient] = copy_bytes(recipient_cipher_base64);
        emit TransferCipher(sender, recipient, bytes(amount.toString()));

        return true;
    }

    function _rlp_decode_as_bytes(bytes memory rlp_encoded) private pure returns (bytes memory) {
        return rlp_encoded.toRlpItem().toBytes();
    }

    function _call_eigen_call(
        bytes memory arg1,
        bytes memory arg2,
        bytes memory arg3,
        bytes memory arg4
    ) private pure returns (bytes memory) {
        // TODO: Now we use RLP encoding in `ecall`, it'd be better using `abi.encode`
        //       to save gas
        bytes[] memory list;

        list = new bytes[](4);

        list[0] = RLPEncode.encodeBytes(arg1);
        list[1] = RLPEncode.encodeBytes(arg2);
        list[2] = RLPEncode.encodeBytes(arg3);
        list[3] = RLPEncode.encodeBytes(arg4);
        bytes memory input = RLPEncode.encodeList(list);

        bytes memory result = ArbSys(address(100)).eigenCall(input);
        require(_compare_bytes(result, RLPEncode.encodeBytes("")) != true, "Eigencall returns an empty string which means we encounter error" );
        return _rlp_decode_as_bytes(result);
    }

    function encrypt(uint256 plain) public pure returns (bytes memory) {
        return _call_eigen_call("encrypt", bytes(plain.toString()), "", "");
    }

    function decrypt(bytes memory cipher) public pure returns (bytes memory) {
        return _call_eigen_call("decrypt", cipher, "", "");
    }

    function addCipherCipher(bytes memory cipher1, bytes memory cipher2)
        public
        pure
        returns (bytes memory)
    {
        return _call_eigen_call("add_cipher_cipher", cipher1, cipher2, "");
    }

    function addCipherPlain(bytes memory cipher, uint256 plain) public pure returns (bytes memory) {
        return _call_eigen_call("add_cipher_plain", cipher, bytes(plain.toString()), "");
    }

    function subCipherCipher(bytes memory cipher1, bytes memory cipher2)
        public
        pure
        returns (bytes memory)
    {
        return _call_eigen_call("sub_cipher_cipher", cipher1, cipher2, "");
    }

    function subCipherPlain(bytes memory cipher, uint256 plain) public pure returns (bytes memory) {
        return _call_eigen_call("sub_cipher_plain", cipher, bytes(plain.toString()), "");
    }

    function _compare_bytes(bytes memory a, bytes memory b) private pure returns (bool) {
        return keccak256(a) == keccak256(b);
    }

    function compareCipherCipher(bytes memory cipher1, bytes memory cipher2)
        public
        pure
        returns (int256)
    {
        bytes memory compare_result = _call_eigen_call(
            "compare_cipher_cipher",
            cipher1,
            cipher2,
            ""
        );
        require(
            _compare_bytes(compare_result, "0") ||
                _compare_bytes(compare_result, "1") ||
                _compare_bytes(compare_result, "-1"),
            "compare result can only be -1, 0, or 1"
        );

        if (_compare_bytes(compare_result, "-1")) {
            return -1;
        } else if (_compare_bytes(compare_result, "1")) {
            return 1;
        } else {
            return 0;
        }
    }

    function compareCipherPlain(bytes memory cipher, uint256 plain) public pure returns (int256) {
        bytes memory compare_result = _call_eigen_call(
            "compare_cipher_plain",
            cipher,
            bytes(plain.toString()),
            ""
        );
        require(
            _compare_bytes(compare_result, "0") ||
                _compare_bytes(compare_result, "1") ||
                _compare_bytes(compare_result, "-1"),
            "compare result can only be -1, 0, or 1"
        );

        if (_compare_bytes(compare_result, "-1")) {
            return -1;
        } else if (_compare_bytes(compare_result, "1")) {
            return 1;
        } else {
            return 0;
        }
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
}
