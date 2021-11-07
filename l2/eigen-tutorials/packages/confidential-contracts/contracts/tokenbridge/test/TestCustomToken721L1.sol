// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.6.11;

import "../libraries/eERC721.sol";
import "../ethereum/ICustomToken721.sol";
import "../ethereum/EthERC20Bridge.sol";
import "@openzeppelin/contracts/GSN/Context.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
//import "@openzeppelin/contracts/math/SafeMath.sol";

contract TestCustomToken721L1 is eERC721, ICustomToken721 {
    EthERC20Bridge public bridge;

    constructor(address _bridge) public {
        bridge = EthERC20Bridge(_bridge);
        eERC721.initialize("TestERC721", "ENFT");
    }

    function mint() external {
        _mint(msg.sender, 0);
    }

    function transferFrom(
        address sender,
        address recipient,
        uint256 tokenId
    ) public override(ERC721Upgradeable, ICustomToken721) {
        ERC721Upgradeable.transferFrom(sender, recipient, tokenId);
    }

    function balanceOf(address account)
        public
        view
        override(ERC721Upgradeable, ICustomToken721)
        returns (uint256)
    {
        return ERC721Upgradeable.balanceOf(account);
    }


    function registerTokenOnL2(
        address l2CustomTokenAddress,
        uint256 maxSubmissionCost,
        uint256 maxGas,
        uint256 gasPriceBid,
        address refundAddress
    ) public override {
        bridge.registerCustomL2Token(
            l2CustomTokenAddress,
            maxSubmissionCost,
            maxGas,
            gasPriceBid,
            refundAddress
        );
    }
}
