// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/** 
 * @dev Used in events to indicate the list type that an account or 
 * @dev codehash is being added to or removed from.
 * 
 * @dev Used in Creator Token Standards V2.
 */
enum ListTypes {
    // 0: List type that will block a matching address/codehash that is on the list.
    Blacklist,

    // 1: List type that will block any matching address/codehash that is not on the list.
    Whitelist
}

/** 
 * @dev Used in events to indicate the list type that event relates to.
 * 
 * @dev Used in Creator Token Standards V1.
 */
enum AllowlistTypes {
    // 0: List type that defines the allowed operator addresses.
    Operators,

    // 1: List type that defines the allowed contract receivers.
    PermittedContractReceivers
}

/**
 @dev Defines the constraints that will be applied for receipt of tokens.
 */
enum ReceiverConstraints {
    // 0: Any address may receive tokens.
    None,

    // 1: Address must not have deployed bytecode.
    NoCode,

    // 2: Address must verify a signature with the EOA Registry to prove it is an EOA.
    EOA
}

/**
 * @dev Defines the constraints that will be applied to the transfer caller.
 */
enum CallerConstraints {
    // 0: Any address may transfer tokens.
    None,

    // 1: Addresses and codehashes not on the blacklist may transfer tokens.
    OperatorBlacklistEnableOTC,

    // 2: Addresses and codehashes on the whitelist and the owner of the token may transfer tokens.
    OperatorWhitelistEnableOTC,

    // 3: Addresses and codehashes on the whitelist may transfer tokens.
    OperatorWhitelistDisableOTC
}

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
 * @dev Used in both Creator Token Standards V1 and V2.
 * @dev Levels may have different transfer restrictions in V1 and V2. Refer to the 
 * @dev Creator Token Transfer Validator implementation for the version being utilized
 * @dev to determine the effect of the selected level.
 */
enum TransferSecurityLevels {
    Recommended,
    One,
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
    Eight
}

/**
 * @dev Defines the caller and receiver constraints for a transfer security level.
 * @dev Used in Creator Token Standards V1.
 * 
 * @dev **callerConstraints**: The restrictions applied to the transfer caller.
 * @dev **receiverConstraints**: The restrictions applied to the transfer recipient.
 */
struct TransferSecurityPolicy {
    CallerConstraints callerConstraints;
    ReceiverConstraints receiverConstraints;
}

/**
 * @dev Defines the security policy for a token collection in Creator Token Standards V1.
 * 
 * @dev **transferSecurityLevel**: The transfer security level set for the collection.
 * @dev **operatorWhitelistId**: The list id for the operator whitelist.
 * @dev **permittedContractReceiversId: The list id for the contracts that are allowed to receive tokens.
 */
struct CollectionSecurityPolicy {
    TransferSecurityLevels transferSecurityLevel;
    uint120 operatorWhitelistId;
    uint120 permittedContractReceiversId;
}

/**
 * @dev Defines the security policy for a token collection in Creator Token Standards V2.
 * 
 * @dev **transferSecurityLevel**: The transfer security level set for the collection.
 * @dev **listId**: The list id that contains the blacklist and whitelist to apply to the collection.
 */
struct CollectionSecurityPolicyV2 {
    TransferSecurityLevels transferSecurityLevel;
    uint120 listId;
}

/**
 * @dev Defines the security policy for a token collection in Creator Token Standards V2.
 * 
 * @dev **transferSecurityLevel**: The transfer security level set for the collection.
 * @dev **listId**: The list id that contains the blacklist and whitelist to apply to the collection.
 * @dev **enableGraylisting**: If true, graylisting will be enabled for the collection.
 */
struct CollectionSecurityPolicyV3 {
    bool enableAuthorizationMode;
    uint8 transferSecurityLevel;
    uint120 listId;
}

/** 
 * @dev Used internally in the Creator Token Base V2 contract to pack transfer validator configuration.
 * 
 * @dev **isInitialized**: If not initialized by the collection owner or admin the default validator will be used.
 * @dev **version**: The transfer validator version.
 * @dev **transferValidator**: The address of the transfer validator to use for applying collection security settings.
 */
struct TransferValidatorReference {
    bool isInitialized;
    uint16 version;
    address transferValidator;
}