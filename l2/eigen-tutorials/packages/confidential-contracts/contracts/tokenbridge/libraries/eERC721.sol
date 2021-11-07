// SPDX-License-Identifier: Apache-2.0
import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";

pragma solidity ^0.6.11;

contract eERC721 is ERC721Upgradeable {
    using AddressUpgradeable for address;

    function initialize(
        string memory name,
        string memory symbol
    ) public initializer {
        __ERC721_init(name, symbol);
    }
}

