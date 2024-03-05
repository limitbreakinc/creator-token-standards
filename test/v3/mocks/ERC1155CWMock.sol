// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import "src/access/OwnableBasic.sol";
import "src/erc1155c/v2/extensions/ERC1155CW.sol";

contract ERC1155CWMock is OwnableBasic, ERC1155CW {
    constructor(address wrappedCollectionAddress_) ERC1155CW(wrappedCollectionAddress_) ERC1155OpenZeppelin("") {}

    function mint(address, /*to*/ uint256 tokenId, uint256 amount) external {
        stake(tokenId, amount);
    }
}
