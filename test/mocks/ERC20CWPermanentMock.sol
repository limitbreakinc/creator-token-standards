// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import "src/access/OwnableBasic.sol";
import "src/access/OwnableInitializable.sol";
import "src/erc20c/presets/ERC20CWPermanent.sol";

contract ERC20CWPermanentMock is OwnableBasic, ERC20CWPermanent {
    constructor(address wrappedCollectionAddress_, uint8 decimals_)
        ERC20CW(wrappedCollectionAddress_)
        ERC20OpenZeppelin("ERC20CWPermanentMock", "E20CWPM", decimals_) 
    {}

    function mint(address, /*to*/ uint256 amount) external {
        stake(amount);
    }
}
