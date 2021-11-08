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
import "../libraries/EigenCallLibrary.sol";

contract TestCCCustomToken is aeERC20, IArbToken {
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
        aeERC20.initialize("TestCCCustomToken", "xEIG", uint8(18));
    }

    function someWackyCustomStuff() public {}

    function cipherBalanceOf(address account, bytes memory secret)
        public
        view
        returns (bytes memory)
    {
        bytes memory balance = _cipher_balances[account];
        // re-encrypt by user's secret
        return EigenCallLibrary.reEncrypt(secret, balance);
        //return decrypt(balance);
    }

    function bridgeMint(address account, uint256 amount) external override onlyBridge {
        _mint(account, amount);

        bytes memory cipher_hex = EigenCallLibrary.encrypt(amount);
        _cipher_balances[account] = EigenCallLibrary.copyBytes(cipher_hex);
    }

    function bridgeBurn(address account, uint256 amount) external override onlyBridge {
        _burn(account, amount);

        bytes memory cipher_hex_balance = _cipher_balances[account];
        bytes memory cipher_hex = EigenCallLibrary.subCipherPlain(cipher_hex_balance, amount);
        _cipher_balances[account] = EigenCallLibrary.copyBytes(cipher_hex);
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

        bytes memory sender_cipher_hex_balance = _cipher_balances[_msgSender()];
        bytes memory sender_cipher_hex = EigenCallLibrary.subCipherCipher(
            sender_cipher_hex_balance,
            cipher_amount
        );
        _cipher_balances[_msgSender()] = EigenCallLibrary.copyBytes(sender_cipher_hex);

        bytes memory recipient_cipher_hex_balance = _cipher_balances[recipient];
        bytes memory recipient_cipher_hex = EigenCallLibrary.addCipherCipher(
            recipient_cipher_hex_balance,
            cipher_amount
        );
        _cipher_balances[recipient] = EigenCallLibrary.copyBytes(recipient_cipher_hex);
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

        bytes memory sender_cipher_hex_balance = _cipher_balances[sender];
        bytes memory sender_cipher_hex = EigenCallLibrary.subCipherCipher(
            sender_cipher_hex_balance,
            cipher_amount
        );
        _cipher_balances[sender] = EigenCallLibrary.copyBytes(sender_cipher_hex);

        bytes memory recipient_cipher_hex_balance = _cipher_balances[recipient];
        bytes memory recipient_cipher_hex = EigenCallLibrary.addCipherCipher(
            recipient_cipher_hex_balance,
            cipher_amount
        );
        _cipher_balances[recipient] = EigenCallLibrary.copyBytes(recipient_cipher_hex);
        emit TransferCipher(sender, recipient, bytes(cipher_amount));

        return true;
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);

        require(_msgSender() != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        bytes[] memory list;
        list = new bytes[](4);

        bytes memory sender_cipher_hex_balance = _cipher_balances[_msgSender()];
        bytes memory sender_cipher_hex = EigenCallLibrary.subCipherPlain(
            sender_cipher_hex_balance,
            amount
        );
        _cipher_balances[_msgSender()] = EigenCallLibrary.copyBytes(sender_cipher_hex);

        bytes memory recipient_cipher_hex_balance = _cipher_balances[recipient];
        bytes memory recipient_cipher_hex = EigenCallLibrary.addCipherPlain(
            recipient_cipher_hex_balance,
            amount
        );
        _cipher_balances[recipient] = EigenCallLibrary.copyBytes(recipient_cipher_hex);
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

        bytes memory sender_cipher_hex_balance = _cipher_balances[sender];
        bytes memory sender_cipher_hex = EigenCallLibrary.subCipherPlain(
            sender_cipher_hex_balance,
            amount
        );
        _cipher_balances[sender] = EigenCallLibrary.copyBytes(sender_cipher_hex);

        bytes memory recipient_cipher_hex_balance = _cipher_balances[recipient];
        bytes memory recipient_cipher_hex = EigenCallLibrary.addCipherPlain(
            recipient_cipher_hex_balance,
            amount
        );
        _cipher_balances[recipient] = EigenCallLibrary.copyBytes(recipient_cipher_hex);
        emit TransferCipher(sender, recipient, bytes(amount.toString()));
        return true;
    }

    function demo_encrypt(uint256 plain) public pure returns (bytes memory) {
        bytes memory output = EigenCallLibrary.encrypt(plain);
        return output;
    }

    function demo_decrypt(bytes memory cipher) public pure returns (bytes memory) {
        bytes memory output = EigenCallLibrary.decrypt(cipher);

        return output;
    }

    function demo_addCipherCipher(bytes memory cipher1, bytes memory cipher2)
        public
        pure
        returns (bytes memory)
    {
        bytes memory output = EigenCallLibrary.addCipherCipher(cipher1, cipher2);
        return output;
    }

    function demo_addCipherPlain(bytes memory cipher, uint256 plain)
        public
        pure
        returns (bytes memory)
    {
        bytes memory output = EigenCallLibrary.addCipherPlain(cipher, plain);
        return output;
    }

    function demo_subCipherCipher(bytes memory cipher1, bytes memory cipher2)
        public
        pure
        returns (bytes memory)
    {
        bytes memory output = EigenCallLibrary.subCipherCipher(cipher1, cipher2);
        return output;
    }

    function demo_subCipherPlain(bytes memory cipher, uint256 plain)
        public
        pure
        returns (bytes memory)
    {
        bytes memory output = EigenCallLibrary.subCipherPlain(cipher, plain);
        return output;
    }

    function demo_compareCipherCipher(bytes memory cipher1, bytes memory cipher2)
        public
        pure
        returns (int256)
    {
        int256 result = EigenCallLibrary.compareCipherCipher(cipher1, cipher2);
        return result;
    }

    function demo_compareCipherPlain(bytes memory cipher, uint256 plain)
        public
        pure
        returns (int256)
    {
        int256 result = EigenCallLibrary.compareCipherPlain(cipher, plain);
        return result;
    }
}
