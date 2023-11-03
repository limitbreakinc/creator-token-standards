// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import "../../src/access/OwnableBasic.sol";
import "../../src/access/OwnableInitializable.sol";
import "../../src/erc721c/ERC721C.sol";

contract ERC721CMock is OwnableBasic, ERC721C {
    constructor() ERC721OpenZeppelin("ERC-721C Mock", "MOCK") {}

    function mint(address to, uint256 tokenId) external {
        _mint(to, tokenId);
    }
}

contract ERC721CInitializableMock is OwnableInitializable, ERC721CInitializable {
    constructor() ERC721("", "") {}

    function mint(address to, uint256 tokenId) external {
        _mint(to, tokenId);
    }
}
