// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import "src/access/OwnableBasic.sol";
import "src/erc721c/presets/ERC721CWPermanent.sol";

contract ERC721CWPermanentMock is OwnableBasic, ERC721CWPermanent {
    constructor(address wrappedCollectionAddress_)
        ERC721CW(wrappedCollectionAddress_)
        ERC721OpenZeppelin("ERC-721C Mock", "MOCK")
    {}

    function mint(address, /*to*/ uint256 tokenId) external {
        stake(tokenId);
    }
}
