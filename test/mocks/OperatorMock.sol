// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

contract OperatorMock {
    uint256 public immutable salt;
    constructor(uint256 salt_) {
        salt = salt_;
    }

    function transfer721(address collection, address from, address to, uint256 tokenId) external {
        IERC721(collection).transferFrom(from, to, tokenId);
    }

    function transfer1155(address collection, address from, address to, uint256 tokenId, uint256 amount) external {
        IERC1155(collection).safeTransferFrom(from, to, tokenId, amount, "");
    }
}
