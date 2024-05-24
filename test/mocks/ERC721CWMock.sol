// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import "src/access/OwnableBasic.sol";
import "src/access/OwnableInitializable.sol";
import "src/erc721c/extensions/ERC721CW.sol";

contract ERC721CWMock is OwnableBasic, ERC721CW {
    constructor(address wrappedCollectionAddress_)
        ERC721CW(wrappedCollectionAddress_)
        ERC721OpenZeppelin("ERC-721C Mock", "MOCK")
    {}

    function mint(address, /*to*/ uint256 tokenId) external {
        stake(tokenId);
    }
}

contract ERC721CWInitializableMock is OwnableInitializable, ERC721CWInitializable {
    constructor() ERC721("", "") {}

    function mint(address, /*to*/ uint256 tokenId) external {
        stake(tokenId);
    }
}
