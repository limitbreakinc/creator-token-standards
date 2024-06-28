// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import "src/access/OwnableBasic.sol";
import "src/access/OwnableInitializable.sol";
import "src/erc20c/presets/ERC20CWPermanent.sol";

contract ERC20CWPermanentMock is OwnableBasic, ERC20CWPermanent {
    uint8 private _decimals;

    constructor(address wrappedCollectionAddress_, uint8 decimals_)
        ERC20CW(wrappedCollectionAddress_)
        ERC20("ERC20CWPermanentMock", "E20CWPM") {
        _decimals = decimals_;
    }

    function mint(address, /*to*/ uint256 amount) external {
        stake(amount);
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }
}
