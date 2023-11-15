// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import "src/access/OwnablePermissions.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

abstract contract ERC20OpenZeppelinBase is ERC20 {

    // Token name
    string internal _contractName;

    // Token symbol
    string internal _contractSymbol;

    function name() public view virtual override returns (string memory) {
        return _contractName;
    }

    function symbol() public view virtual override returns (string memory) {
        return _contractSymbol;
    }

    function _setNameAndSymbol(string memory name_, string memory symbol_) internal {
        _contractName = name_;
        _contractSymbol = symbol_;
    }
}

abstract contract ERC20OpenZeppelin is ERC20OpenZeppelinBase {
    constructor(string memory name_, string memory symbol_) ERC20("", "") {
        _setNameAndSymbol(name_, symbol_);
    }
}

abstract contract ERC20OpenZeppelinInitializable is OwnablePermissions, ERC20OpenZeppelinBase {

    error ERC20OpenZeppelinInitializable__AlreadyInitializedERC20();

    /// @notice Specifies whether or not the contract is initialized
    bool private _erc20Initialized;

    /// @dev Initializes parameters of ERC721 tokens.
    /// These cannot be set in the constructor because this contract is optionally compatible with EIP-1167.
    function initializeERC20(string memory name_, string memory symbol_) public {
        _requireCallerIsContractOwner();

        if(_erc20Initialized) {
            revert ERC20OpenZeppelinInitializable__AlreadyInitializedERC20();
        }

        _erc20Initialized = true;

        _setNameAndSymbol(name_, symbol_);
    }
}
