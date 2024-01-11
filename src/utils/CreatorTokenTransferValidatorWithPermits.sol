// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./CreatorTokenTransferValidatorV2.sol";
import "@limitbreak/permit-c/PermitC.sol";

/**
 * @title  CreatorTokenTransferValidatorWithPermits
 * @author Limit Break, Inc.
 * @notice Extends the Creator Token Transfer Validator V2 contract, adding Permit-C support.
 */
contract CreatorTokenTransferValidatorWithPermits is CreatorTokenTransferValidatorV2, PermitC {

    /// @dev NO ERROR bytes4 selector flag
    bytes4 private constant SELECTOR_NO_ERROR = bytes4(0x00000000);

    constructor(
        address defaultOwner, 
        string memory name, 
        string memory version
    ) 
    CreatorTokenTransferValidatorV2(defaultOwner) 
    PermitC(name, version) {}

    /**
     * @notice Apply the collection transfer policy to a transfer operation of a creator token.
     *
     * @dev Throws when the receiver has deployed code and isn't whitelisted, if ReceiverConstraints.NoCode is set.
     * @dev Throws when the receiver has never verified a signature to prove they are an EOA and the receiver
     *      isn't whitelisted, if the ReceiverConstraints.EOA is set.
     * @dev Throws when `msg.sender` is blacklisted, if CallerConstraints.OperatorBlacklistEnableOTC is set, unless
     *      `msg.sender` is also the `from` address.
     * @dev Throws when `msg.sender` isn't whitelisted, if CallerConstraints.OperatorWhitelistEnableOTC is set, unless
     *      `msg.sender` is also the `from` address.
     * @dev Throws when neither `msg.sender` nor `from` are whitelisted, if 
     *      CallerConstraints.OperatorWhitelistDisableOTC is set.
     *
     * @dev <h4>Postconditions:</h4>
     *      1. Transfer is allowed or denied based on the applied transfer policy.
     *
     * @param caller The address initiating the transfer.
     * @param from   The address of the token owner.
     * @param to     The address of the token receiver.
     */
     function applyCollectionTransferPolicy(address caller, address from, address to) external view override {
        bytes4 errorSelector = _applyCollectionTransferPolicy(caller, from, to);
        if (errorSelector != SELECTOR_NO_ERROR) {
            _revertCustomErrorSelectorAsm(errorSelector);
        }
     }

    /**
     * @dev Hook that is called before any permitted token transfer that goes through Permit-C.
     *      Applies the collection transfer policy, using the operator that called Permit-C as the caller.
     *      This allows creator token standard protections to extend to permitted transfers.
     */
    function _beforeTransferFrom(
        address token, 
        address from, 
        address to, 
        uint256 id, 
        uint256 amount
    ) internal override returns (bool isError) {
        isError = _applyCollectionTransferPolicy(msg.sender, from, to) != SELECTOR_NO_ERROR;
    }

    /**
     * @notice Apply the collection transfer policy to a transfer operation of a creator token.
     *
     * @dev If the caller is self (Permit-C Processor) it means we have already applied operator validation in the 
     *      _beforeTransferFrom callback.  In this case, the security policy was already applied and the operator
     *      that used the Permit-C processor passed the security policy check and transfer can be safely allowed.
     *
     * @dev Throws when the receiver has deployed code and isn't whitelisted, if ReceiverConstraints.NoCode is set.
     * @dev Throws when the receiver has never verified a signature to prove they are an EOA and the receiver
     *      isn't whitelisted, if the ReceiverConstraints.EOA is set.
     * @dev Throws when `msg.sender` is blacklisted, if CallerConstraints.OperatorBlacklistEnableOTC is set, unless
     *      `msg.sender` is also the `from` address.
     * @dev Throws when `msg.sender` isn't whitelisted, if CallerConstraints.OperatorWhitelistEnableOTC is set, unless
     *      `msg.sender` is also the `from` address.
     * @dev Throws when neither `msg.sender` nor `from` are whitelisted, if 
     *      CallerConstraints.OperatorWhitelistDisableOTC is set.
     *
     * @dev <h4>Postconditions:</h4>
     *      1. Transfer is allowed or denied based on the applied transfer policy.
     *
     * @param caller The address initiating the transfer.
     * @param from   The address of the token owner.
     * @param to     The address of the token receiver.
     */
    function _applyCollectionTransferPolicy(address caller, address from, address to) internal view returns (bytes4) {
        if (caller == address(this)) { 
            // If the caller is self (Permit-C Processor) it means we have already applied operator validation in the 
            // _beforeTransferFrom callback.  In this case, the security policy was already applied and the operator
            // that used the Permit-C processor passed the security policy check and transfer can be safely allowed.
            return SELECTOR_NO_ERROR;
        }

        CollectionSecurityPolicyV2 storage collectionSecurityPolicy = collectionSecurityPolicies[_msgSender()];
        uint120 listId = collectionSecurityPolicy.listId;
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) = 
            transferSecurityPolicies(collectionSecurityPolicy.transferSecurityLevel);

        List storage whitelist = whitelists[listId];

        if (receiverConstraints == ReceiverConstraints.NoCode) {
            if (_getCodeLengthAsm(to) > 0) {
                if (!whitelist.nonEnumerableAccounts[to]) {
                    if (!whitelist.nonEnumerableCodehashes[_getCodeHashAsm(to)]) {
                        return CreatorTokenTransferValidator__ReceiverMustNotHaveDeployedCode.selector;
                    }
                }
            }

            
        } else if (receiverConstraints == ReceiverConstraints.EOA) {
            if (!isVerifiedEOA(to)) {
                if (!whitelist.nonEnumerableAccounts[to]) {
                    if (!whitelist.nonEnumerableCodehashes[_getCodeHashAsm(to)]) {
                        return CreatorTokenTransferValidator__ReceiverProofOfEOASignatureUnverified.selector;
                    }
                }
            }
        }

        if (caller == from) {
            if (callerConstraints != CallerConstraints.OperatorWhitelistDisableOTC) {
                return SELECTOR_NO_ERROR;
            }
        }

        if (callerConstraints == CallerConstraints.OperatorBlacklistEnableOTC) {
            List storage blacklist = blacklists[listId];
            if (blacklist.nonEnumerableAccounts[caller]) {
                return CreatorTokenTransferValidator__OperatorIsBlacklisted.selector;
            }

            if (blacklist.nonEnumerableCodehashes[_getCodeHashAsm(caller)]) {
                return CreatorTokenTransferValidator__OperatorIsBlacklisted.selector;
            }
        } else if (callerConstraints == CallerConstraints.OperatorWhitelistEnableOTC) {
            if (whitelist.nonEnumerableAccounts[caller]) {
                return SELECTOR_NO_ERROR;
            }

            if (whitelist.nonEnumerableCodehashes[_getCodeHashAsm(caller)]) {
                return SELECTOR_NO_ERROR;
            }

            return CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector;
        } else if (callerConstraints == CallerConstraints.OperatorWhitelistDisableOTC) {
            mapping(address => bool) storage accountWhitelist = whitelist.nonEnumerableAccounts;

            if (accountWhitelist[caller]) {
                return SELECTOR_NO_ERROR;
            }

            if (accountWhitelist[from]) {
                return SELECTOR_NO_ERROR;
            }

            mapping(bytes32 => bool) storage codehashWhitelist = whitelist.nonEnumerableCodehashes;

            if (codehashWhitelist[_getCodeHashAsm(caller)]) {
                return SELECTOR_NO_ERROR;
            }

            if (codehashWhitelist[_getCodeHashAsm(from)]) {
                return SELECTOR_NO_ERROR;
            }

            return CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector;
        }

        return SELECTOR_NO_ERROR;
    }

    /**
     * @dev Internal function used to efficiently revert with a custom error selector.
     *
     * @param errorSelector The error selector to revert with.
     */
    function _revertCustomErrorSelectorAsm(bytes4 errorSelector) internal pure {
        assembly {
            mstore(0x00, errorSelector)
            revert(0x00, 0x04)
        }
    }
}