pragma solidity ^0.8.4;

import "./ERC20.sol";
import "../../access/OwnablePermissions.sol";

abstract contract ERC20Initializable is OwnablePermissions, ERC20 {
    constructor() ERC20("", "") { }

    error ERC20Initializable__AlreadyInitializedERC20();

    /// @notice Specifies whether or not the contract is initialized
    bool private _erc20Initialized;

    /// @dev Initializes parameters of ERC721 tokens.
    /// These cannot be set in the constructor because this contract is optionally compatible with EIP-1167.
    function initializeERC20(string memory name_, string memory symbol_) public virtual {
        _requireCallerIsContractOwner();

        if(_erc20Initialized) {
            revert ERC20Initializable__AlreadyInitializedERC20();
        }

        _erc20Initialized = true;

        storageERC20().name = name_;
        storageERC20().symbol = symbol_;
    }
}
