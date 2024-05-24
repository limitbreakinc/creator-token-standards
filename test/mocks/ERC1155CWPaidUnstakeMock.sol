// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import "src/access/OwnableBasic.sol";
import "src/erc1155c/presets/ERC1155CWPaidUnstake.sol";

contract ERC1155CWPaidUnstakeMock is OwnableBasic, ERC1155CWPaidUnstake {
    constructor(uint256 unstakeUnitPrice_, address wrappedCollectionAddress_)
        ERC1155CWPaidUnstake(unstakeUnitPrice_, wrappedCollectionAddress_, "")
    {}

    function mint(address, /*to*/ uint256 tokenId, uint256 amount) external {
        stake(tokenId, amount);
    }
}
