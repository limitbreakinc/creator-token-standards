// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import "src/access/OwnableBasic.sol";
import "src/access/OwnableInitializable.sol";
import "src/erc20c/presets/ERC20CWPaidUnstake.sol";

contract ERC20CWPaidUnstakeMock is OwnableBasic, ERC20CWPaidUnstake {
    constructor(
        uint256 unstakeUnitPrice_, 
        address wrappedCollectionAddress_, 
        uint8 decimals_
    ) ERC20CWPaidUnstake(unstakeUnitPrice_, wrappedCollectionAddress_, "ERC20CWPaidUnstakeMock", "ERC20CWPUM", decimals_) {}

    function mint(address, /*to*/ uint256 amount) external {
        stake(amount);
    }
}
