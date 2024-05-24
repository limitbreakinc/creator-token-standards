// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "../extensions/ERC20CW.sol";

/**
 * @title ERC20CWPaidUnstake
 * @author Limit Break, Inc.
 * @notice Extension of ERC20CW that enforces a payment to unstake the wrapped token.
 */
abstract contract ERC20CWPaidUnstake is ERC20CW {

    error ERC20CWPaidUnstake__IncorrectUnstakePayment();
    
    /// @dev The price required to unstake.  This cannot be modified after contract creation.
    uint256 immutable private unstakeUnitPrice;

    constructor(
        uint256 unstakeUnitPrice_, 
        address wrappedCollectionAddress_, 
        string memory name_, 
        string memory symbol_,
        uint8 decimals_) ERC20CW(wrappedCollectionAddress_) ERC20OpenZeppelin(name_, symbol_, decimals_) {
        unstakeUnitPrice = unstakeUnitPrice_;
    }

    /// @notice Returns the price, in wei, required to unstake per one item.
    function getUnstakeUnitPrice() external view returns (uint256) {
        return unstakeUnitPrice;
    }

    /// @dev Reverts if the unstaking payment is not exactly equal to the unstaking price.
    function _onUnstake(uint256 amount, uint256 value) internal virtual override {
        if(value != amount * unstakeUnitPrice) {
            revert ERC20CWPaidUnstake__IncorrectUnstakePayment();
        }
    }
}
