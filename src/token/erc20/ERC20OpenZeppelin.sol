// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import "../../access/OwnablePermissions.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

abstract contract ERC20OpenZeppelinBase is ERC20 {

    // Token name
    string internal _contractName;

    // Token symbol
    string internal _contractSymbol;

    // Token decimals
    uint8 internal _decimals;

    function name() public view virtual override returns (string memory) {
        return _contractName;
    }

    function symbol() public view virtual override returns (string memory) {
        return _contractSymbol;
    }

    function decimals() public view virtual override returns (uint8) {
        return _decimals;
    }

    function _setNameSymbolAndDecimals(string memory name_, string memory symbol_, uint8 decimals_) internal {
        _contractName = name_;
        _contractSymbol = symbol_;
        _decimals = decimals_;
    }
}

abstract contract ERC20OpenZeppelin is ERC20OpenZeppelinBase {
    constructor(string memory name_, string memory symbol_, uint8 decimals_) ERC20("", "") {
        _setNameSymbolAndDecimals(name_, symbol_, decimals_);
    }
}

abstract contract ERC20OpenZeppelinInitializable is OwnablePermissions, ERC20OpenZeppelinBase {
    constructor() ERC20("", "") { }

    error ERC20OpenZeppelinInitializable__AlreadyInitializedERC20();

    /// @notice Specifies whether or not the contract is initialized
    bool private _erc20Initialized;

    /// @dev Initializes parameters of ERC721 tokens.
    /// These cannot be set in the constructor because this contract is optionally compatible with EIP-1167.
    function initializeERC20(string memory name_, string memory symbol_, uint8 decimals_) public virtual {
        _requireCallerIsContractOwner();

        if(_erc20Initialized) {
            revert ERC20OpenZeppelinInitializable__AlreadyInitializedERC20();
        }

        _erc20Initialized = true;

        _setNameSymbolAndDecimals(name_, symbol_, decimals_);
    }
}
