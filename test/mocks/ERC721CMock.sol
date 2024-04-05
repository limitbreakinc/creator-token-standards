// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import "./templates/constructable/erc721c/ERC721CMetadata.sol";
import "./templates/cloneable/erc721c/ERC721CMetadataInitializable.sol";

contract ERC721CMock is ERC721CMetadata {
    constructor() ERC721CMetadata("ERC-721C Mock", "MOCK") {}

    function mint(address to, uint256 tokenId) external {
        _mint(to, tokenId);
    }
}

contract ERC721CInitializableMock is ERC721CMetadataInitializable {
    constructor() ERC721("", "") {}

    function mint(address to, uint256 tokenId) external {
        _mint(to, tokenId);
    }
}
