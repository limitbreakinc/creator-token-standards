// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/**
 * @dev Defines constraints for staking tokens in token wrapper contracts.
 */
enum StakerConstraints {
    // 0: No constraints applied to staker.
    None,

    // 1: Transaction originator must be the address that will receive the wrapped tokens.
    CallerIsTxOrigin,

    // 2: Address that will receive the wrapped tokens must be a verified EOA.
    EOA
}

/**
 * @dev Defines the security policy for a token collection in Creator Token Standards V2.
 * 
 * @dev **transferSecurityLevel**: The transfer security level set for the collection.
 * @dev **listId**: The list id that contains the blacklist and whitelist to apply to the collection.
 * @dev **enableGraylisting**: If true, graylisting will be enabled for the collection.
 */
struct CollectionSecurityPolicyV3 {
    bool disableAuthorizationMode;
    bool authorizersCannotSetWildcardOperators;
    uint8 transferSecurityLevel;
    uint120 listId;
    bool enableAccountFreezingMode;
    uint16 tokenType;
}