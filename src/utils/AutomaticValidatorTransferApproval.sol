// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "../access/OwnablePermissions.sol";

/**
 * @title AutomaticValidatorTransferApproval
 * @author Limit Break, Inc.
 * @notice Base contract mix-in that provides boilerplate code giving the contract owner the
 *         option to automatically approve a 721-C transfer validator implementation for transfers.
 */
abstract contract AutomaticValidatorTransferApproval is OwnablePermissions {

    /// @dev Emitted when the automatic approval flag is modified by the creator.
    event AutomaticApprovalOfTransferValidatorSet(bool autoApproved);

    /// @dev If true, the collection's transfer validator is automatically approved to transfer holder's tokens.
    bool public autoApproveTransfersFromValidator;

    /**
     * @notice Sets if the transfer validator is automatically approved as an operator for all token owners.
     * 
     * @dev    Throws when the caller is not the contract owner.
     * 
     * @param autoApprove If true, the collection's transfer validator will be automatically approved to
     *                    transfer holder's tokens.
     */
    function setAutomaticApprovalOfTransfersFromValidator(bool autoApprove) external {
        _requireCallerIsContractOwner();
        autoApproveTransfersFromValidator = autoApprove;
        emit AutomaticApprovalOfTransferValidatorSet(autoApprove);
    }
}