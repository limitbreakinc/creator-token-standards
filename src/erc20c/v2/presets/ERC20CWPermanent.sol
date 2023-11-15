// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "../extensions/ERC20CW.sol";

/**
 * @title ERC20CWPermanent
 * @author Limit Break, Inc.
 * @notice Extension of ERC20CW that permanently stakes the wrapped token.
 */
abstract contract ERC20CWPermanent is ERC20CW {

    error ERC20CWPermanent__UnstakeIsNotPermitted();

    /// @notice Permanent Creator Tokens Are Never Unstakeable
    function canUnstake(uint256 /*amount*/) public virtual view override returns (bool) {
        return false;
    }

    /// @dev Reverts on any attempt to unstake.
    function _onUnstake(uint256 /*amount*/, uint256 /*value*/) internal virtual override {
        revert ERC20CWPermanent__UnstakeIsNotPermitted();
    }
}
