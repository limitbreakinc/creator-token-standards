// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import "src/access/OwnableBasic.sol";
import "src/access/OwnableInitializable.sol";
import "src/erc20c/extensions/ERC20CW.sol";

contract ERC20CWMock is OwnableBasic, ERC20CW {
    constructor(address wrappedCollectionAddress_, uint8 decimals_)
        ERC20CW(wrappedCollectionAddress_)
        ERC20OpenZeppelin("ERC20CWMock", "E20CWM", decimals_) 
    {}

    function mint(address, /*to*/ uint256 amount) external {
        stake(amount);
    }
}

contract ERC20CWInitializableMock is OwnableInitializable, ERC20CWInitializable {

    function mint(address, /*to*/ uint256 amount) external {
        stake(amount);
    }
}
