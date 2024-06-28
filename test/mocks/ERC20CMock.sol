// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "src/erc20c/ERC20C.sol";
import "src/erc20c/ERC20CInitializable.sol";
import "src/access/OwnableBasic.sol";
import "src/access/OwnableInitializable.sol";

contract ERC20CMock is OwnableBasic, ERC20C {
    uint8 private _decimals;

    constructor(uint8 decimals_) ERC20("ERC20CMock", "E20CM") { 
        _decimals = decimals_;
    }

    function mint(address account, uint256 amount) external {
        _mint(account, amount);
    }

    function burn(address account, uint256 amount) external {
        _burn(account, amount);
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }
}


contract ERC20CInitializableMock is OwnableInitializable, ERC20CInitializable {

    function mint(address to, uint256 tokenId) external {
        _mint(to, tokenId);
    }

    function burn(address account, uint256 amount) external {
        _burn(account, amount);
    }
}
