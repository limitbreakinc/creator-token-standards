// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import "src/access/OwnableBasic.sol";
import "src/erc721c/presets/ERC721CWTimeLockedUnstake.sol";

contract ERC721CWTimeLockedUnstakeMock is OwnableBasic, ERC721CWTimeLockedUnstake {
    constructor(uint256 timelockSeconds_, address wrappedCollectionAddress_)
        ERC721CWTimeLockedUnstake(timelockSeconds_, wrappedCollectionAddress_, "ERC-721C Mock", "MOCK")
    {}

    function mint(address, /*to*/ uint256 tokenId) external {
        stake(tokenId);
    }
}
