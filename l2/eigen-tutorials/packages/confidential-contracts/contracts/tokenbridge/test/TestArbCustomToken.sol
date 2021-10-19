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
import "./EigenCallHelper.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract TestArbCustomToken is aeERC20, IArbToken {
    using EigenCallHelper for *;
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
        _cipher_balances[account] = EigenCallHelper.copy_bytes(cipher_base64);
    }

    function bridgeBurn(address account, uint256 amount) external override onlyBridge {
        _burn(account, amount);

        bytes memory cipher_base64_balance = _cipher_balances[account];
        bytes memory cipher_base64 = EigenCallHelper.subCipherPlain(cipher_base64_balance, amount);
        _cipher_balances[account] = EigenCallHelper.copy_bytes(cipher_base64);
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
        bytes memory sender_cipher_base64 = EigenCallHelper.subCipherCipher(
            sender_cipher_base64_balance,
            cipher_amount
        );
        _cipher_balances[_msgSender()] = EigenCallHelper.copy_bytes(sender_cipher_base64);

        bytes memory recipient_cipher_base64_balance = _cipher_balances[recipient];
        bytes memory recipient_cipher_base64 = EigenCallHelper.addCipherCipher(
            recipient_cipher_base64_balance,
            cipher_amount
        );
        _cipher_balances[recipient] = EigenCallHelper.copy_bytes(recipient_cipher_base64);
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
        bytes memory sender_cipher_base64 = EigenCallHelper.subCipherCipher(sender_cipher_base64_balance, cipher_amount);
        _cipher_balances[sender] = EigenCallHelper.copy_bytes(sender_cipher_base64);

        bytes memory recipient_cipher_base64_balance = _cipher_balances[recipient];
        bytes memory recipient_cipher_base64 = EigenCallHelper.addCipherCipher(
            recipient_cipher_base64_balance,
            cipher_amount
        );
        _cipher_balances[recipient] = EigenCallHelper.copy_bytes(recipient_cipher_base64);
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
        bytes memory sender_cipher_base64 = EigenCallHelper.subCipherPlain(sender_cipher_base64_balance, amount);
        _cipher_balances[_msgSender()] = EigenCallHelper.copy_bytes(sender_cipher_base64);

        bytes memory recipient_cipher_base64_balance = _cipher_balances[recipient];
        bytes memory recipient_cipher_base64 = EigenCallHelper.addCipherPlain(
            recipient_cipher_base64_balance,
            amount
        );
        _cipher_balances[recipient] = EigenCallHelper.copy_bytes(recipient_cipher_base64);
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
        bytes memory sender_cipher_base64 = EigenCallHelper.subCipherPlain(sender_cipher_base64_balance, amount);
        _cipher_balances[sender] = EigenCallHelper.copy_bytes(sender_cipher_base64);

        bytes memory recipient_cipher_base64_balance = _cipher_balances[recipient];
        bytes memory recipient_cipher_base64 = EigenCallHelper.addCipherPlain(
            recipient_cipher_base64_balance,
            amount
        );
        _cipher_balances[recipient] = EigenCallHelper.copy_bytes(recipient_cipher_base64);
        emit TransferCipher(sender, recipient, bytes(amount.toString()));

        return true;
    }

    function cipherBalanceOf(address account, bytes memory secret) public view returns (bytes memory) {
        bytes memory balance = _cipher_balances[account];
        // re-encrypt by user's secret
        return EigenCallHelper.re_encrypt(balance, secret);
    }

    // for DEBUG
    function encrypt(uint256 plain) public pure returns (bytes memory) {
        return EigenCallHelper.execute("encrypt1", bytes(plain.toString()), "", "");
    }

    // for DEBUG
    function decrypt(bytes memory cipher) public pure returns (bytes memory) {
        return EigenCallHelper.execute("decrypt1", cipher, "", "");
    }
}
