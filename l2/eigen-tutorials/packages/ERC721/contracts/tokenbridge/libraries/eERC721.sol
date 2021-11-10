// SPDX-License-Identifier: Apache-2.0
import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

pragma solidity ^0.6.11;

contract eERC721 is ERC721Upgradeable, IERC721Receiver {
    using AddressUpgradeable for address;

    function initialize(
        string memory name,
        string memory symbol
    ) public initializer {
        __ERC721_init(name, symbol);
    }

    function onERC721Received(address, address, uint256, bytes memory) public virtual override returns (bytes4) {
        return this.onERC721Received.selector;
    }

}

