// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/**
 * @dev Constant definitions for receiver constraints used by the transfer validator.
 */
/// @dev No constraints on the receiver of a token.
uint256 constant RECEIVER_CONSTRAINTS_NONE = 0;

/// @dev Token receiver cannot have deployed code.
uint256 constant RECEIVER_CONSTRAINTS_NO_CODE = 1;

/// @dev Token receiver must be a verified EOA with the EOA Registry.
uint256 constant RECEIVER_CONSTRAINTS_EOA = 2;

/// @dev Token is a soulbound token and cannot be transferred.
uint256 constant RECEIVER_CONSTRAINTS_SBT = 3;

/**
 * @dev Constant definitions for caller constraints used by the transfer validator.
 */
/// @dev No constraints on the caller of a token transfer.
uint256 constant CALLER_CONSTRAINTS_NONE = 0;

/// @dev Caller of a token transfer must not be on the blacklist unless it is an OTC transfer.
uint256 constant CALLER_CONSTRAINTS_OPERATOR_BLACKLIST_ENABLE_OTC = 1;

/// @dev Caller of a token transfer must be on the whitelist unless it is an OTC transfer.
uint256 constant CALLER_CONSTRAINTS_OPERATOR_WHITELIST_ENABLE_OTC = 2;

/// @dev Caller of a token transfer must be on the whitelist.
uint256 constant CALLER_CONSTRAINTS_OPERATOR_WHITELIST_DISABLE_OTC = 3;

/// @dev Token is a soulbound token and cannot be transferred.
uint256 constant CALLER_CONSTRAINTS_SBT = 4;


/**
 * @dev Constant definitions for transfer security levels used by the transfer validator
 *      to define what receiver and caller constraints are applied to a transfer.
 */

/// @dev Recommend Security Level -
///        Caller Constraints: Operator Whitelist
///        Receiver Constraints: None
///        OTC: Allowed
uint8 constant TRANSFER_SECURITY_LEVEL_RECOMMENDED = 0;

/// @dev Security Level One -
///        Caller Constraints: None
///        Receiver Constraints: None
///        OTC: Allowed
uint8 constant TRANSFER_SECURITY_LEVEL_ONE = 1;

/// @dev Security Level Two -
///        Caller Constraints: Operator Blacklist
///        Receiver Constraints: None
///        OTC: Allowed
uint8 constant TRANSFER_SECURITY_LEVEL_TWO = 2;

/// @dev Security Level Three -
///        Caller Constraints: Operator Whitelist
///        Receiver Constraints: None
///        OTC: Allowed
uint8 constant TRANSFER_SECURITY_LEVEL_THREE = 3;

/// @dev Security Level Four -
///        Caller Constraints: Operator Whitelist
///        Receiver Constraints: None
///        OTC: Not Allowed
uint8 constant TRANSFER_SECURITY_LEVEL_FOUR = 4;

/// @dev Security Level Five -
///        Caller Constraints: Operator Whitelist
///        Receiver Constraints: No Code
///        OTC: Allowed
uint8 constant TRANSFER_SECURITY_LEVEL_FIVE = 5;

/// @dev Security Level Six -
///        Caller Constraints: Operator Whitelist
///        Receiver Constraints: Verified EOA
///        OTC: Allowed
uint8 constant TRANSFER_SECURITY_LEVEL_SIX = 6;

/// @dev Security Level Seven -
///        Caller Constraints: Operator Whitelist
///        Receiver Constraints: No Code
///        OTC: Not Allowed
uint8 constant TRANSFER_SECURITY_LEVEL_SEVEN = 7;

/// @dev Security Level Eight -
///        Caller Constraints: Operator Whitelist
///        Receiver Constraints: Verified EOA
///        OTC: Not Allowed
uint8 constant TRANSFER_SECURITY_LEVEL_EIGHT = 8;

/// @dev Security Level Nine -
///        Soulbound Token, No Transfers Allowed
uint8 constant TRANSFER_SECURITY_LEVEL_NINE = 9;

/// @dev List type is a blacklist.
uint8 constant LIST_TYPE_BLACKLIST = 0;

/// @dev List type is a whitelist.
uint8 constant LIST_TYPE_WHITELIST = 1;

/// @dev List type is authorizers.
uint8 constant LIST_TYPE_AUTHORIZERS = 2;

/// @dev Constant value for the no error selector.
bytes4 constant SELECTOR_NO_ERROR = bytes4(0x00000000);