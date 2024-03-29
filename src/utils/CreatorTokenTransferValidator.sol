// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../Constants.sol";
import "../interfaces/IEOARegistry.sol";
import "../interfaces/IOwnable.sol";
import "../interfaces/ITransferValidator.sol";
import "@limitbreak/permit-c/PermitC.sol";
import "@openzeppelin/contracts/access/IAccessControl.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title  CreatorTokenTransferValidator
 * @author Limit Break, Inc.
 * @notice The CreatorTokenTransferValidator contract is designed to provide a customizable and secure transfer 
 *         validation mechanism for NFT collections. This contract allows the owner of an NFT collection to configure 
 *         the transfer security level, blacklisted accounts and codehashes, whitelisted accounts and codehashes, and
 *         authorized accounts and codehashes for each collection.
 *
 * @dev    <h4>Features</h4>
 *         - Transfer security levels: Provides different levels of transfer security, 
 *           from open transfers to completely restricted transfers.
 *         - Blacklist: Allows the owner of a collection to blacklist specific operator addresses or codehashes
 *           from executing transfers on behalf of others.
 *         - Whitelist: Allows the owner of a collection to whitelist specific operator addresses or codehashes
 *           permitted to execute transfers on behalf of others or send/receive tokens when otherwise disabled by 
 *           security policy.
 *         - Authorizers: Allows the owner of a collection to enable authorizer contracts, that can perform 
 *           authorization-based filtering of transfers.
 *
 * @dev    <h4>Benefits</h4>
 *         - Enhanced security: Allows creators to have more control over their NFT collections, ensuring the safety 
 *           and integrity of their assets.
 *         - Flexibility: Provides collection owners the ability to customize transfer rules as per their requirements.
 *         - Compliance: Facilitates compliance with regulations by enabling creators to restrict transfers based on 
 *           specific criteria.
 *
 * @dev    <h4>Intended Usage</h4>
 *         - The CreatorTokenTransferValidatorV3 contract is intended to be used by NFT collection owners to manage and 
 *           enforce transfer policies. This contract is integrated with the following varations of creator token 
 *           NFT contracts to validate transfers according to the defined security policies.
 *
 *           - ERC721-C:   Creator token implenting OpenZeppelin's ERC-721 standard.
 *           - ERC721-AC:  Creator token implenting Azuki's ERC-721A standard.
 *           - ERC721-CW:  Creator token implementing OpenZeppelin's ERC-721 standard with opt-in staking to 
 *                         wrap/upgrade a pre-existing ERC-721 collection.
 *           - ERC721-ACW: Creator token implementing Azuki's ERC721-A standard with opt-in staking to 
 *                         wrap/upgrade a pre-existing ERC-721 collection.
 *           - ERC1155-C:  Creator token implenting OpenZeppelin's ERC-1155 standard.
 *           - ERC1155-CW: Creator token implementing OpenZeppelin's ERC-1155 standard with opt-in staking to 
 *                         wrap/upgrade a pre-existing ERC-1155 collection.
 *
 *          <h4>Transfer Security Levels</h4>
 *          - Recommended: Recommended defaults are same as Level 3 (Whitelisting with OTC Enabled).
 *            - Caller Constraints: OperatorWhitelistEnableOTC
 *            - Receiver Constraints: None
 *          - Level 1: No transfer restrictions.
 *            - Caller Constraints: None
 *            - Receiver Constraints: None
 *          - Level 2: Only non-blacklisted operators can initiate transfers, over-the-counter (OTC) trading enabled.
 *            - Caller Constraints: OperatorBlacklistEnableOTC
 *            - Receiver Constraints: None
 *          - Level 3: Only whitelisted accounts can initiate transfers, over-the-counter (OTC) trading enabled.
 *            - Caller Constraints: OperatorWhitelistEnableOTC
 *            - Receiver Constraints: None
 *          - Level 4: Only whitelisted accounts can initiate transfers, over-the-counter (OTC) trading disabled.
 *            - Caller Constraints: OperatorWhitelistDisableOTC
 *            - Receiver Constraints: None
 *          - Level 5: Only whitelisted accounts can initiate transfers, over-the-counter (OTC) trading enabled. 
 *                     Transfers to contracts with code are not allowed, unless present on the whitelist.
 *            - Caller Constraints: OperatorWhitelistEnableOTC
 *            - Receiver Constraints: NoCode
 *          - Level 6: Only whitelisted accounts can initiate transfers, over-the-counter (OTC) trading enabled. 
 *                     Transfers are allowed only to Externally Owned Accounts (EOAs), unless present on the whitelist.
 *            - Caller Constraints: OperatorWhitelistEnableOTC
 *            - Receiver Constraints: EOA
 *          - Level 7: Only whitelisted accounts can initiate transfers, over-the-counter (OTC) trading disabled. 
 *                     Transfers to contracts with code are not allowed, unless present on the whitelist.
 *            - Caller Constraints: OperatorWhitelistDisableOTC
 *            - Receiver Constraints: NoCode
 *          - Level 8: Only whitelisted accounts can initiate transfers, over-the-counter (OTC) trading disabled. 
 *                     Transfers are allowed only to Externally Owned Accounts (EOAs), unless present on the whitelist.
 *            - Caller Constraints: OperatorWhitelistDisableOTC
 *            - Receiver Constraints: EOA
 */
contract CreatorTokenTransferValidator is IEOARegistry, ITransferValidator, ERC165, PermitC {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // Custom Errors

    /// @dev Thrown when attempting to set a list id that does not exist.
    error CreatorTokenTransferValidator__ListDoesNotExist();

    /// @dev Thrown when attempting to transfer the ownership of a list to the zero address.
    error CreatorTokenTransferValidator__ListOwnershipCannotBeTransferredToZeroAddress();

    /// @dev Thrown when attempting to call a function that requires the caller to be the list owner.
    error CreatorTokenTransferValidator__CallerDoesNotOwnList();

    /// @dev Thrown when validating a transfer for a collection using whitelists and the operator is not on the whitelist.
    error CreatorTokenTransferValidator__CallerMustBeWhitelisted();

    /// @dev Thrown when authorizing a transfer for a collection using authorizers and the msg.sender is not in the authorizer list.
    error CreatorTokenTransferValidator__CallerMustBeAnAuthorizer();

    /// @dev Thrown when attempting to call a function that requires owner or default admin role for a collection that the caller does not have.
    error CreatorTokenTransferValidator__CallerMustHaveElevatedPermissionsForSpecifiedNFT();

    /// @dev Thrown when constructor args are not valid
    error CreatorTokenTransferValidator__InvalidConstructorArgs();

    /// @dev Thrown when setting the transfer security level to an invalid value.
    error CreatorTokenTransferValidator__InvalidTransferSecurityLevel();

    /// @dev Thrown when validating a transfer for a collection using blacklists and the operator is on the blacklist.
    error CreatorTokenTransferValidator__OperatorIsBlacklisted();

    /// @dev Thrown when validating a transfer for a collection that does not allow receiver to have code and the receiver has code.
    error CreatorTokenTransferValidator__ReceiverMustNotHaveDeployedCode();

    /// @dev Thrown when validating a transfer for a collection that requires receivers be verified EOAs and the receiver is not verified.
    error CreatorTokenTransferValidator__ReceiverProofOfEOASignatureUnverified();

    /// @dev Thrown when a frozen account is the receiver of a transfer
    error CreatorTokenTransferValidator__ReceiverAccountIsFrozen();

    /// @dev Thrown when a frozen account is the sender of a transfer
    error CreatorTokenTransferValidator__SenderAccountIsFrozen();

    /// @dev Thrown when validating a transfer for a collection that is in soulbound token mode.
    error CreatorTokenTransferValidator__TokenIsSoulbound();

    /// @dev Thrown when an authorizer attempts to set a wildcard authorized operator on collections that don't allow wildcards
    error CreatorTokenTransferValidator__WildcardOperatorsCannotBeAuthorizedForCollection();

    /// @dev Thrown when attempting to set a authorized operator when authorization mode is disabled.
    error CreatorTokenTransferValidator__AuthorizationDisabledForCollection();

    event CreatedList(uint256 indexed id, string name);
    event AppliedListToCollection(address indexed collection, uint120 indexed id);
    event ReassignedListOwnership(uint256 indexed id, address indexed newOwner);
    event AccountFrozenForCollection(address indexed collection, address indexed account);
    event AccountUnfrozenForCollection(address indexed collection, address indexed account);
    event AddedAccountToList(uint8 indexed kind, uint256 indexed id, address indexed account);
    event AddedCodeHashToList(uint8 indexed kind, uint256 indexed id, bytes32 indexed codehash);
    event RemovedAccountFromList(uint8 indexed kind, uint256 indexed id, address indexed account);
    event RemovedCodeHashFromList(uint8 indexed kind, uint256 indexed id, bytes32 indexed codehash);
    event SetTransferSecurityLevel(address indexed collection, uint8 level);
    event SetAuthorizationModeEnabled(address indexed collection, bool enabled, bool authorizersCanSetWildcardOperators);
    event SetAccountFreezingModeEnabled(address indexed collection, bool enabled);

    // Structs
    /**
     * @dev This struct is internally for the storage of account and codehash lists.
     */
    struct List {
        EnumerableSet.AddressSet enumerableAccounts;
        EnumerableSet.Bytes32Set enumerableCodehashes;
        mapping (address => bool) nonEnumerableAccounts;
        mapping (bytes32 => bool) nonEnumerableCodehashes;
    }

    struct AccountList {
        EnumerableSet.AddressSet enumerableAccounts;
        mapping (address => bool) nonEnumerableAccounts;
    }

    struct CollectionTokenIdAndAmount {
        address collection;
        uint256 tokenId;
        uint256 amount;
    }

    // Immutable lookup tables
    uint256 private immutable _callerConstraintsLookup;
    uint256 private immutable _receiverConstraintsLookup;
    address private immutable _eoaRegistry;
    
    // Constants

    /// @dev The legacy Creator Token Transfer Validator Interface
    bytes4 private constant LEGACY_TRANSFER_VALIDATOR_INTERFACE_ID = 0x00000000;

    /// @dev The default admin role value for contracts that implement access control.
    bytes32 private constant DEFAULT_ACCESS_CONTROL_ADMIN_ROLE = 0x00;
    /// @dev Value representing a zero value code hash.
    bytes32 private constant BYTES32_ZERO = 0x0000000000000000000000000000000000000000000000000000000000000000;

    address private constant WILDCARD_OPERATOR_ADDRESS = address(0x01);

    uint8 private AUTHORIZATION_TYPES_UNSET = 0;
    uint8 private AUTHORIZATION_TYPES_COLLECTION = 1;
    uint8 private AUTHORIZATION_TYPES_TOKEN_ID = 2;
    uint8 private AUTHORIZATION_TYPES_TOKEN_ID_AND_AMOUNT = 3;

    /// @notice Keeps track of the most recently created list id.
    uint120 public lastListId;

    /// @notice Mapping of list ids to list owners
    mapping (uint120 => address) public listOwners;

    /// @dev Mapping of collection addresses to their security policy settings
    mapping (address => CollectionSecurityPolicyV3) internal collectionSecurityPolicies;

    /// @dev Mapping of list ids to blacklist settings
    mapping (uint120 => List) internal blacklists;

    /// @dev Mapping of list ids to whitelist settings
    mapping (uint120 => List) internal whitelists;

    /// @dev Mapping of list ids to authorizers
    mapping (uint120 => List) internal authorizers;

    /// @dev Mapping of collections to accounts that are frozen for those collections
    mapping (address => AccountList) internal frozenAccounts;

    constructor(
        address defaultOwner,
        address eoaRegistry_,
        string memory name,
        string memory version
    ) 
    PermitC(name, version) {
        if (defaultOwner == address(0) || eoaRegistry_ == address(0)) {
            revert CreatorTokenTransferValidator__InvalidConstructorArgs();
        }

        uint120 id = 0;

        listOwners[id] = defaultOwner;

        emit CreatedList(id, "DEFAULT LIST");
        emit ReassignedListOwnership(id, defaultOwner);

        _callerConstraintsLookup =
            (CALLER_CONSTRAINTS_OPERATOR_WHITELIST_ENABLE_OTC << (TRANSFER_SECURITY_LEVEL_RECOMMENDED << 3))
            | (CALLER_CONSTRAINTS_NONE << (TRANSFER_SECURITY_LEVEL_ONE << 3))
            | (CALLER_CONSTRAINTS_OPERATOR_BLACKLIST_ENABLE_OTC << (TRANSFER_SECURITY_LEVEL_TWO << 3))
            | (CALLER_CONSTRAINTS_OPERATOR_WHITELIST_ENABLE_OTC << (TRANSFER_SECURITY_LEVEL_THREE << 3))
            | (CALLER_CONSTRAINTS_OPERATOR_WHITELIST_DISABLE_OTC << (TRANSFER_SECURITY_LEVEL_FOUR << 3))
            | (CALLER_CONSTRAINTS_OPERATOR_WHITELIST_ENABLE_OTC << (TRANSFER_SECURITY_LEVEL_FIVE << 3))
            | (CALLER_CONSTRAINTS_OPERATOR_WHITELIST_ENABLE_OTC << (TRANSFER_SECURITY_LEVEL_SIX << 3))
            | (CALLER_CONSTRAINTS_OPERATOR_WHITELIST_DISABLE_OTC << (TRANSFER_SECURITY_LEVEL_SEVEN << 3))
            | (CALLER_CONSTRAINTS_OPERATOR_WHITELIST_DISABLE_OTC << (TRANSFER_SECURITY_LEVEL_EIGHT << 3))
            | (CALLER_CONSTRAINTS_SBT << (TRANSFER_SECURITY_LEVEL_NINE << 3));

        _receiverConstraintsLookup = 
            (RECEIVER_CONSTRAINTS_NONE << (TRANSFER_SECURITY_LEVEL_RECOMMENDED << 3))
            | (RECEIVER_CONSTRAINTS_NONE << (TRANSFER_SECURITY_LEVEL_ONE << 3))
            | (RECEIVER_CONSTRAINTS_NONE << (TRANSFER_SECURITY_LEVEL_TWO << 3))
            | (RECEIVER_CONSTRAINTS_NONE << (TRANSFER_SECURITY_LEVEL_THREE << 3))
            | (RECEIVER_CONSTRAINTS_NONE << (TRANSFER_SECURITY_LEVEL_FOUR << 3))
            | (RECEIVER_CONSTRAINTS_NO_CODE << (TRANSFER_SECURITY_LEVEL_FIVE << 3))
            | (RECEIVER_CONSTRAINTS_EOA << (TRANSFER_SECURITY_LEVEL_SIX << 3))
            | (RECEIVER_CONSTRAINTS_NO_CODE << (TRANSFER_SECURITY_LEVEL_SEVEN << 3))
            | (RECEIVER_CONSTRAINTS_EOA << (TRANSFER_SECURITY_LEVEL_EIGHT << 3))
            | (RECEIVER_CONSTRAINTS_SBT << (TRANSFER_SECURITY_LEVEL_NINE << 3));

        _eoaRegistry = eoaRegistry_;
    }

    /*************************************************************************/
    /*                               MODIFIERS                               */
    /*************************************************************************/

    /**
     * @dev This modifier restricts a function call to the owner of the list `id`.
     * @dev Throws when the caller is not the list owner.
     */
    modifier onlyListOwner(uint120 id) {
        _requireCallerOwnsList(id);
        _;
    }

    /*************************************************************************/
    /*                          APPLY TRANSFER POLICIES                      */
    /*************************************************************************/

    /// Ensure that a specific operator has been authorized to transfer tokens
    function validateTransfer(address caller, address from, address to) public view {
        bytes4 errorSelector = _validateTransfer(msg.sender, caller, from, to, 0);
        if (errorSelector != SELECTOR_NO_ERROR) {
            _revertCustomErrorSelectorAsm(errorSelector);
        }
    }

    /// Ensure that a transfer has been authorized for a specific tokenId
    function validateTransfer(address caller, address from, address to, uint256 tokenId) public view {
        bytes4 errorSelector = _validateTransfer(msg.sender, caller, from, to, tokenId);
        if (errorSelector != SELECTOR_NO_ERROR) {
            _revertCustomErrorSelectorAsm(errorSelector);
        }
    }

    /// Ensure that a transfer has been authorized for a specific tokenId and amount
    function validateTransfer(address caller, address from, address to, uint256 tokenId, uint256 /*amount*/) external {
        validateTransfer(caller, from, to, tokenId);
    }

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
    function applyCollectionTransferPolicy(address caller, address from, address to) external view {
        validateTransfer(caller, from, to);
    }

    /**
     * @notice Returns the caller and receiver constraints for the specified transfer security level.
     * 
     * @param level The transfer security level to return the caller and receiver constraints for.
     * 
     * @return callerConstraints    The `CallerConstraints` value for the level.
     * @return receiverConstraints The `ReceiverConstraints` value for the level.
     */
    function transferSecurityPolicies(
        uint256 level
    ) public view returns (uint256 callerConstraints, uint256 receiverConstraints) {
        callerConstraints = uint8((_callerConstraintsLookup >> (level << 3)));
        receiverConstraints = uint8((_receiverConstraintsLookup >> (level << 3)));
    }

    function beforeAuthorizedTransfer(address operator, address token, uint256 tokenId) public {
        _setOperatorInTransientStorage(operator, token, tokenId);
    }

    function afterAuthorizedTransfer(address token, uint256 tokenId) public {
        _setOperatorInTransientStorage(address(uint160(uint256(BYTES32_ZERO))), token, tokenId);
    }

    // Shims

    function beforeAuthorizedTransfer(address operator, address token) external {
        beforeAuthorizedTransfer(operator, token, 0);
    }

    function afterAuthorizedTransfer(address token) external {
        afterAuthorizedTransfer(token, 0);
    }

    function beforeAuthorizedTransfer(address token, uint256 tokenId) external {
        beforeAuthorizedTransfer(WILDCARD_OPERATOR_ADDRESS, token, tokenId);
    }

    function beforeAuthorizedTransferWithAmount(address token, uint256 tokenId, uint256 /*amount*/) external {
        beforeAuthorizedTransfer(WILDCARD_OPERATOR_ADDRESS, token, tokenId);
    }

    function afterAuthorizedTransferWithAmount(address token, uint256 tokenId) external {
        afterAuthorizedTransfer(token, tokenId);
    }

    /*************************************************************************/
    /*                              LIST MANAGEMENT                          */
    /*************************************************************************/

    /**
     * @notice Creates a new list id.  The list id is a handle to allow editing of blacklisted and whitelisted accounts
     *         and codehashes.
     *
     * @dev <h4>Postconditions:</h4>
     *      1. A new list with the specified name is created.
     *      2. The caller is set as the owner of the new list.
     *      3. A `CreatedList` event is emitted.
     *      4. A `ReassignedListOwnership` event is emitted.
     *
     * @param  name The name of the new list.
     * @return id   The id of the new list.
     */
    function createList(string calldata name) public returns (uint120 id) {
        id = ++lastListId;

        listOwners[id] = msg.sender;

        emit CreatedList(id, name);
        emit ReassignedListOwnership(id, msg.sender);
    }

    /**
     * @notice Creates a new list id, and copies all blacklisted and whitelisted accounts and codehashes from the
     *         specified source list.
     *
     * @dev    <h4>Postconditions:</h4>
     *         1. A new list with the specified name is created.
     *         2. The caller is set as the owner of the new list.
     *         3. A `CreatedList` event is emitted.
     *         4. A `ReassignedListOwnership` event is emitted.
     *         5. All blacklisted and whitelisted accounts and codehashes from the specified source list are copied
     *            to the new list.
     *         6. An `AddedAccountToList` event is emitted for each blacklisted and whitelisted account copied.
     *         7. An `AddedCodeHashToList` event is emitted for each blacklisted and whitelisted codehash copied.
     *
     * @param  name         The name of the new list.
     * @param  sourceListId The id of the source list to copy from.
     * @return id           The id of the new list.
     */
    function createListCopy(string calldata name, uint120 sourceListId) external returns (uint120 id) {
        id = ++lastListId;

        unchecked {
            if (sourceListId > id - 1) {
                revert CreatorTokenTransferValidator__ListDoesNotExist();
            }
        }

        listOwners[id] = msg.sender;

        emit CreatedList(id, name);
        emit ReassignedListOwnership(id, msg.sender);

        List storage sourceBlacklist = blacklists[sourceListId];
        List storage sourceWhitelist = whitelists[sourceListId];
        List storage sourceAuthorizers = authorizers[sourceListId];
        List storage targetBlacklist = blacklists[id];
        List storage targetWhitelist = whitelists[id];
        List storage targetAuthorizers = authorizers[id];

        _copyAddressSet(LIST_TYPE_BLACKLIST, id, sourceBlacklist, targetBlacklist);
        _copyBytes32Set(LIST_TYPE_BLACKLIST, id, sourceBlacklist, targetBlacklist);
        _copyAddressSet(LIST_TYPE_WHITELIST, id, sourceWhitelist, targetWhitelist);
        _copyBytes32Set(LIST_TYPE_WHITELIST, id, sourceWhitelist, targetWhitelist);
        _copyAddressSet(LIST_TYPE_AUTHORIZERS, id, sourceAuthorizers, targetAuthorizers);
        _copyBytes32Set(LIST_TYPE_AUTHORIZERS, id, sourceAuthorizers, targetAuthorizers);
    }

    /**
     * @notice Transfer ownership of a list to a new owner.
     *
     * @dev Throws when the new owner is the zero address.
     * @dev Throws when the caller does not own the specified list.
     *
     * @dev <h4>Postconditions:</h4>
     *      1. The list ownership is transferred to the new owner.
     *      2. A `ReassignedListOwnership` event is emitted.
     *
     * @param id       The id of the list.
     * @param newOwner The address of the new owner.
     */
    function reassignOwnershipOfList(uint120 id, address newOwner) public {
        if(newOwner == address(0)) {
            revert CreatorTokenTransferValidator__ListOwnershipCannotBeTransferredToZeroAddress();
        }

        _reassignOwnershipOfList(id, newOwner);
    }

    /**
     * @notice Renounce the ownership of a list, rendering the list immutable.
     *
     * @dev Throws when the caller does not own the specified list.
     *
     * @dev <h4>Postconditions:</h4>
     *      1. The ownership of the specified list is renounced.
     *      2. A `ReassignedListOwnership` event is emitted.
     *
     * @param id The id of the list.
     */
    function renounceOwnershipOfList(uint120 id) public {
        _reassignOwnershipOfList(id, address(0));
    }

    /**
     * @notice Set the transfer security level of a collection.
     *
     * @dev Throws when the caller is neither collection contract, nor the owner or admin of the specified collection.
     *
     * @dev <h4>Postconditions:</h4>
     *      1. The transfer security level of the specified collection is set to the new value.
     *      2. A `SetTransferSecurityLevel` event is emitted.
     *
     * @param collection The address of the collection.
     * @param level      The new transfer security level to apply.
     */
    function setTransferSecurityLevelOfCollection(
        address collection, 
        uint8 level,
        bool enableAuthorizationMode,
        bool authorizersCanSetWildcardOperators,
        bool enableAccountFreezingMode) external {

        if (level > TRANSFER_SECURITY_LEVEL_NINE) {
            revert CreatorTokenTransferValidator__InvalidTransferSecurityLevel();
        }

        _requireCallerIsNFTOrContractOwnerOrAdmin(collection);
        collectionSecurityPolicies[collection].transferSecurityLevel = level;
        collectionSecurityPolicies[collection].enableAuthorizationMode = enableAuthorizationMode;
        collectionSecurityPolicies[collection].authorizersCanSetWildcardOperators = authorizersCanSetWildcardOperators;
        collectionSecurityPolicies[collection].enableAccountFreezingMode = enableAccountFreezingMode;
        emit SetTransferSecurityLevel(collection, level);
        emit SetAuthorizationModeEnabled(collection, enableAuthorizationMode, authorizersCanSetWildcardOperators);
        emit SetAccountFreezingModeEnabled(collection, enableAccountFreezingMode);
    }

    /**
     * @notice Applies the specified list to a collection.
     * 
     * @dev Throws when the caller is neither collection contract, nor the owner or admin of the specified collection.
     * @dev Throws when the specified list id does not exist.
     *
     * @dev <h4>Postconditions:</h4>
     *      1. The list of the specified collection is set to the new value.
     *      2. An `AppliedListToCollection` event is emitted.
     *
     * @param collection The address of the collection.
     * @param id         The id of the operator whitelist.
     */
    function applyListToCollection(address collection, uint120 id) public {
        _requireCallerIsNFTOrContractOwnerOrAdmin(collection);

        if (id > lastListId) {
            revert CreatorTokenTransferValidator__ListDoesNotExist();
        }

        collectionSecurityPolicies[collection].listId = id;
        emit AppliedListToCollection(collection, id);
    }

    function freezeAccountsForCollection(address collection, address[] calldata accountsToFreeze) external {
        _requireCallerIsNFTOrContractOwnerOrAdmin(collection);

        AccountList storage accounts = frozenAccounts[collection];

        for (uint256 i = 0; i < accountsToFreeze.length;) {
            address accountToFreeze = accountsToFreeze[i];

            if (accounts.enumerableAccounts.add(accountToFreeze)) {
                emit AccountFrozenForCollection(collection, accountToFreeze);
                accounts.nonEnumerableAccounts[accountToFreeze] = true;
            }

            unchecked {
                ++i;
            }
        }
    }

    function unfreezeAccountsForCollection(address collection, address[] calldata accountsToUnfreeze) external {
        _requireCallerIsNFTOrContractOwnerOrAdmin(collection);

        AccountList storage accounts = frozenAccounts[collection];

        for (uint256 i = 0; i < accountsToUnfreeze.length;) {
            address accountToUnfreeze = accountsToUnfreeze[i];

            if (accounts.enumerableAccounts.remove(accountToUnfreeze)) {
                emit AccountUnfrozenForCollection(collection, accountToUnfreeze);
                accounts.nonEnumerableAccounts[accountToUnfreeze] = false;
            }

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Get the security policy of the specified collection.
     * @param collection The address of the collection.
     * @return           The security policy of the specified collection, which includes:
     *                   Transfer security level, operator whitelist id, permitted contract receiver allowlist id
     */
    function getCollectionSecurityPolicy(address collection) 
        external view returns (CollectionSecurityPolicyV3 memory) {
        return collectionSecurityPolicies[collection];
    }

    /**
     * @notice Adds one or more accounts to a blacklist.
     *
     * @dev Throws when the caller does not own the specified list.
     * @dev Throws when the accounts array is empty.
     *
     * @dev <h4>Postconditions:</h4>
     *      1. Accounts not previously in the list are added.
     *      2. An `AddedAccountToList` event is emitted for each account that is newly added to the list.
     *
     * @param id       The id of the list.
     * @param accounts The addresses of the accounts to add.
     */
    function addAccountsToBlacklist(
        uint120 id, 
        address[] memory accounts
    ) public {
        _addAccountsToList(blacklists[id], LIST_TYPE_BLACKLIST, id, accounts);
    }

    function addAccountToBlacklist(
        uint120 id,
        address account
    ) external {
        addAccountsToBlacklist(id, _asSingletonArray(account));
    }

    /**
     * @notice Adds one or more accounts to a whitelist.
     *
     * @dev Throws when the caller does not own the specified list.
     * @dev Throws when the accounts array is empty.
     *
     * @dev <h4>Postconditions:</h4>
     *      1. Accounts not previously in the list are added.
     *      2. An `AddedAccountToList` event is emitted for each account that is newly added to the list.
     *
     * @param id       The id of the list.
     * @param accounts The addresses of the accounts to add.
     */
    function addAccountsToWhitelist(
        uint120 id, 
        address[] memory accounts
    ) public {
        _addAccountsToList(whitelists[id], LIST_TYPE_WHITELIST, id, accounts);
    }

    function addAccountToWhitelist(
        uint120 id,
        address account
    ) external {
        addAccountsToWhitelist(id, _asSingletonArray(account));
    }

    /**
     * @notice Adds one or more accounts to authorizers.
     *
     * @dev Throws when the caller does not own the specified list.
     * @dev Throws when the accounts array is empty.
     *
     * @dev <h4>Postconditions:</h4>
     *      1. Accounts not previously in the list are added.
     *      2. An `AddedAccountToList` event is emitted for each account that is newly added to the list.
     *
     * @param id       The id of the list.
     * @param accounts The addresses of the accounts to add.
     */
    function addAccountsToAuthorizers(
        uint120 id, 
        address[] memory accounts
    ) public {
        _addAccountsToList(authorizers[id], LIST_TYPE_AUTHORIZERS, id, accounts);
    }

    function addAccountToAuthorizers(
        uint120 id,
        address account
    ) external {
        addAccountsToAuthorizers(id, _asSingletonArray(account));
    }

    /**
     * @notice Adds one or more codehashes to a blacklist.
     *
     * @dev Throws when the caller does not own the specified list.
     * @dev Throws when the codehashes array is empty.
     * @dev Throws when a codehash is zero.
     *
     * @dev <h4>Postconditions:</h4>
     *      1. Codehashes not previously in the list are added.
     *      2. An `AddedCodeHashToList` event is emitted for each codehash that is newly added to the list.
     *
     * @param id         The id of the list.
     * @param codehashes The codehashes to add.
     */
    function addCodeHashesToBlacklist(
        uint120 id, 
        bytes32[] calldata codehashes
    ) external {
        _addCodeHashesToList(blacklists[id], LIST_TYPE_BLACKLIST, id, codehashes);
    }

    /**
     * @notice Adds one or more codehashes to a whitelist.
     *
     * @dev Throws when the caller does not own the specified list.
     * @dev Throws when the codehashes array is empty.
     * @dev Throws when a codehash is zero.
     *
     * @dev <h4>Postconditions:</h4>
     *      1. Codehashes not previously in the list are added.
     *      2. An `AddedCodeHashToList` event is emitted for each codehash that is newly added to the list.
     *
     * @param id         The id of the list.
     * @param codehashes The codehashes to add.
     */
    function addCodeHashesToWhitelist(
        uint120 id, 
        bytes32[] calldata codehashes
    ) external {
        _addCodeHashesToList(whitelists[id], LIST_TYPE_WHITELIST, id, codehashes);
    }

    /**
     * @notice Removes one or more accounts from a blacklist.
     *
     * @dev Throws when the caller does not own the specified list.
     * @dev Throws when the accounts array is empty.
     *
     * @dev <h4>Postconditions:</h4>
     *      1. Accounts previously in the list are removed.
     *      2. A `RemovedAccountFromList` event is emitted for each account that is removed from the list.
     *
     * @param id       The id of the list.
     * @param accounts The addresses of the accounts to remove.
     */
    function removeAccountsFromBlacklist(
        uint120 id, 
        address[] memory accounts
    ) public {
        _removeAccountsFromList(blacklists[id], LIST_TYPE_BLACKLIST, id, accounts);
    }

    function removeAccountFromBlacklist(
        uint120 id,
        address account
    ) external {
        removeAccountsFromBlacklist(id, _asSingletonArray(account));
    }

    /**
     * @notice Removes one or more accounts from a whitelist.
     *
     * @dev Throws when the caller does not own the specified list.
     * @dev Throws when the accounts array is empty.
     *
     * @dev <h4>Postconditions:</h4>
     *      1. Accounts previously in the list are removed.
     *      2. A `RemovedAccountFromList` event is emitted for each account that is removed from the list.
     *
     * @param id       The id of the list.
     * @param accounts The addresses of the accounts to remove.
     */
    function removeAccountsFromWhitelist(
        uint120 id, 
        address[] memory accounts
    ) public {
        _removeAccountsFromList(whitelists[id], LIST_TYPE_WHITELIST, id, accounts);
    }

    function removeAccountFromWhitelist(
        uint120 id,
        address account
    ) external {
        removeAccountsFromWhitelist(id, _asSingletonArray(account));
    }

    /**
     * @notice Removes one or more accounts from authorizers.
     *
     * @dev Throws when the caller does not own the specified list.
     * @dev Throws when the accounts array is empty.
     *
     * @dev <h4>Postconditions:</h4>
     *      1. Accounts previously in the list are removed.
     *      2. A `RemovedAccountFromList` event is emitted for each account that is removed from the list.
     *
     * @param id       The id of the list.
     * @param accounts The addresses of the accounts to remove.
     */
    function removeAccountsFromAuthorizers(
        uint120 id, 
        address[] memory accounts
    ) public {
        _removeAccountsFromList(authorizers[id], LIST_TYPE_AUTHORIZERS, id, accounts);
    }

    function removeAccountFromAuthorizers(
        uint120 id,
        address account
    ) external {
        removeAccountsFromAuthorizers(id, _asSingletonArray(account));
    }

    /**
     * @notice Removes one or more codehashes from a blacklist.
     *
     * @dev Throws when the caller does not own the specified list.
     * @dev Throws when the codehashes array is empty.
     *
     * @dev <h4>Postconditions:</h4>
     *      1. Codehashes previously in the list are removed.
     *      2. A `RemovedCodeHashFromList` event is emitted for each codehash that is removed from the list.
     *
     * @param id         The id of the list.
     * @param codehashes The codehashes to remove.
     */
    function removeCodeHashesFromBlacklist(
        uint120 id, 
        bytes32[] calldata codehashes
    ) external {
        _removeCodeHashesFromList(blacklists[id], LIST_TYPE_BLACKLIST, id, codehashes);
    }

    /**
     * @notice Removes one or more codehashes from a whitelist.
     *
     * @dev Throws when the caller does not own the specified list.
     * @dev Throws when the codehashes array is empty.
     *
     * @dev <h4>Postconditions:</h4>
     *      1. Codehashes previously in the list are removed.
     *      2. A `RemovedCodeHashFromList` event is emitted for each codehash that is removed from the list.
     *
     * @param id         The id of the list.
     * @param codehashes The codehashes to remove.
     */
    function removeCodeHashesFromWhitelist(
        uint120 id, 
        bytes32[] calldata codehashes
    ) external {
        _removeCodeHashesFromList(whitelists[id], LIST_TYPE_WHITELIST, id, codehashes);
    }

    /**
     * @notice Get blacklisted accounts by list id.
     * @param  id The id of the list.
     * @return An array of blacklisted accounts.
     */
    function getBlacklistedAccounts(uint120 id) public view returns (address[] memory) {
        return blacklists[id].enumerableAccounts.values();
    }

    /**
     * @notice Get whitelisted accounts by list id.
     * @param  id The id of the list.
     * @return An array of whitelisted accounts.
     */
    function getWhitelistedAccounts(uint120 id) public view returns (address[] memory) {
        return whitelists[id].enumerableAccounts.values();
    }

    /**
     * @notice Get authorizor accounts by list id.
     * @param  id The id of the list.
     * @return An array of authorizer accounts.
     */
    function getAuthorizerAccounts(uint120 id) public view returns (address[] memory) {
        return authorizers[id].enumerableAccounts.values();
    }

    /**
     * @notice Get blacklisted codehashes by list id.
     * @param id The id of the list.
     * @return   An array of blacklisted codehashes.
     */
    function getBlacklistedCodeHashes(uint120 id) public view returns (bytes32[] memory) {
        return blacklists[id].enumerableCodehashes.values();
    }

    /**
     * @notice Get whitelisted codehashes by list id.
     * @param id The id of the list.
     * @return   An array of whitelisted codehashes.
     */
    function getWhitelistedCodeHashes(uint120 id) public view returns (bytes32[] memory) {
        return whitelists[id].enumerableCodehashes.values();
    }

    /**
     * @notice Check if an account is blacklisted in a specified list.
     * @param id       The id of the list.
     * @param account  The address of the account to check.
     * @return         True if the account is blacklisted in the specified list, false otherwise.
     */
    function isAccountBlacklisted(uint120 id, address account) public view returns (bool) {
        return blacklists[id].nonEnumerableAccounts[account];
    }

    /**
     * @notice Check if an account is whitelisted in a specified list.
     * @param id       The id of the list.
     * @param account  The address of the account to check.
     * @return         True if the account is whitelisted in the specified list, false otherwise.
     */
    function isAccountWhitelisted(uint120 id, address account) public view returns (bool) {
        return whitelists[id].nonEnumerableAccounts[account];
    }

    /**
     * @notice Check if an account is an authorizer in a specified list.
     * @param id       The id of the list.
     * @param account  The address of the account to check.
     * @return         True if the account is an authorizer in the specified list, false otherwise.
     */
    function isAccountAuthorizer(uint120 id, address account) public view returns (bool) {
        return authorizers[id].nonEnumerableAccounts[account];
    }

    /**
     * @notice Check if a codehash is blacklisted in a specified list.
     * @param id       The id of the list.
     * @param codehash  The codehash to check.
     * @return         True if the codehash is blacklisted in the specified list, false otherwise.
     */
    function isCodeHashBlacklisted(uint120 id, bytes32 codehash) public view returns (bool) {
        return blacklists[id].nonEnumerableCodehashes[codehash];
    }

    /**
     * @notice Check if a codehash is whitelisted in a specified list.
     * @param id       The id of the list.
     * @param codehash  The codehash to check.
     * @return         True if the codehash is whitelisted in the specified list, false otherwise.
     */
    function isCodeHashWhitelisted(uint120 id, bytes32 codehash) public view returns (bool) {
        return whitelists[id].nonEnumerableCodehashes[codehash];
    }

    /**
     * @notice Get blacklisted accounts by collection.
     * @param collection The address of the collection.
     * @return           An array of blacklisted accounts.
     */
    function getBlacklistedAccountsByCollection(address collection) external view returns (address[] memory) {
        return getBlacklistedAccounts(collectionSecurityPolicies[collection].listId);
    }

    /**
     * @notice Get whitelisted accounts by collection.
     * @param collection The address of the collection.
     * @return           An array of whitelisted accounts.
     */
    function getWhitelistedAccountsByCollection(address collection) external view returns (address[] memory) {
        return getWhitelistedAccounts(collectionSecurityPolicies[collection].listId);
    }

    /**
     * @notice Get authorizer accounts by collection.
     * @param collection The address of the collection.
     * @return           An array of authorizer accounts.
     */
    function getAuthorizerAccountsByCollection(address collection) external view returns (address[] memory) {
        return getAuthorizerAccounts(collectionSecurityPolicies[collection].listId);
    }

    function getFrozenAccountsByCollection(address collection) external view returns (address[] memory) {
        return frozenAccounts[collection].enumerableAccounts.values();
    }

    /**
     * @notice Get blacklisted codehashes by collection.
     * @param collection The address of the collection.
     * @return           An array of blacklisted codehashes.
     */
    function getBlacklistedCodeHashesByCollection(address collection) external view returns (bytes32[] memory) {
        return getBlacklistedCodeHashes(collectionSecurityPolicies[collection].listId);
    }

    /**
     * @notice Get whitelisted codehashes by collection.
     * @param collection The address of the collection.
     * @return           An array of whitelisted codehashes.
     */
    function getWhitelistedCodeHashesByCollection(address collection) external view returns (bytes32[] memory) {
        return getWhitelistedCodeHashes(collectionSecurityPolicies[collection].listId);
    }

    /**
     * @notice Check if an account is blacklisted by a specified collection.
     * @param collection The address of the collection.
     * @param account    The address of the account to check.
     * @return           True if the account is blacklisted by the specified collection, false otherwise.
     */
    function isAccountBlacklistedByCollection(address collection, address account) external view returns (bool) {
        return isAccountBlacklisted(collectionSecurityPolicies[collection].listId, account);
    }

    /**
     * @notice Check if an account is whitelisted by a specified collection.
     * @param collection The address of the collection.
     * @param account    The address of the account to check.
     * @return           True if the account is whitelisted by the specified collection, false otherwise.
     */
    function isAccountWhitelistedByCollection(address collection, address account) external view returns (bool) {
        return isAccountWhitelisted(collectionSecurityPolicies[collection].listId, account);
    }

    /**
     * @notice Check if an account is an authorizer of a specified collection.
     * @param collection The address of the collection.
     * @param account    The address of the account to check.
     * @return           True if the account is an authorizer by the specified collection, false otherwise.
     */
    function isAccountAuthorizerOfCollection(address collection, address account) external view returns (bool) {
        return isAccountAuthorizer(collectionSecurityPolicies[collection].listId, account);
    }

    function isAccountFrozenForCollection(address collection, address account) external view returns (bool) {
        return frozenAccounts[collection].nonEnumerableAccounts[account];
    }

    /**
     * @notice Check if a codehash is blacklisted by a specified collection.
     * @param collection The address of the collection.
     * @param codehash   The codehash to check.
     * @return           True if the codehash is blacklisted by the specified collection, false otherwise.
     */
    function isCodeHashBlacklistedByCollection(address collection, bytes32 codehash) external view returns (bool) {
        return isCodeHashBlacklisted(collectionSecurityPolicies[collection].listId, codehash);
    }

    /**
     * @notice Check if a codehash is whitelisted by a specified collection.
     * @param collection The address of the collection.
     * @param codehash   The codehash to check.
     * @return           True if the codehash is whitelisted by the specified collection, false otherwise.
     */
    function isCodeHashWhitelistedByCollection(address collection, bytes32 codehash) external view returns (bool) {
        return isCodeHashWhitelisted(collectionSecurityPolicies[collection].listId, codehash);
    }

    /// @notice Returns true if the specified account has verified a signature on the registry, false otherwise.
    function isVerifiedEOA(address account) public view returns (bool) {
        return IEOARegistry(_eoaRegistry).isVerifiedEOA(account);
    }

    /// @notice ERC-165 Interface Support
    /// @dev    Do not remove ITransferSecurityRegistry, ITransferSecurityRegistryV2, ICreatorTokenTransferValidator,
    ///         or ICreatorTokenTransferValidatorV2 from this contract or future contracts.  
    ///         Doing so will break backwards compatibility with V1 and V2 creator tokens.
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == LEGACY_TRANSFER_VALIDATOR_INTERFACE_ID ||
            interfaceId == type(ITransferValidator).interfaceId ||
            interfaceId == type(IPermitC).interfaceId ||
            interfaceId == type(IEOARegistry).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /*************************************************************************/
    /*                                HELPERS                                */
    /*************************************************************************/

    /**
     * @notice Reverts the transaction if the caller is not the owner or assigned the default
     * @notice admin role of the contract at `tokenAddress`.
     *
     * @dev    Throws when the caller is neither owner nor assigned the default admin role.
     * 
     * @param tokenAddress The contract address of the token to check permissions for.
     */
    function _requireCallerIsNFTOrContractOwnerOrAdmin(address tokenAddress) internal view {
        bool callerHasPermissions = false;

        address caller = msg.sender;
        
        callerHasPermissions = caller == tokenAddress;
        if(!callerHasPermissions) {
            (address contractOwner,) = _safeOwner(tokenAddress);
            callerHasPermissions = caller == contractOwner;

            if(!callerHasPermissions) {
                (bool callerIsContractAdmin,) = _safeHasRole(tokenAddress, DEFAULT_ACCESS_CONTROL_ADMIN_ROLE, caller);
                callerHasPermissions = callerIsContractAdmin;
            }
        }

        if(!callerHasPermissions) {
            revert CreatorTokenTransferValidator__CallerMustHaveElevatedPermissionsForSpecifiedNFT();
        }
    }

    /**
     * @notice Copies all addresses in `ptrFromList` to `ptrToList`.
     * 
     * @dev    This function will copy all addresses from one list to another list.
     * @dev    Note: If used to copy adddresses to an existing list the current list contents will not be
     * @dev    deleted before copying. New addresses will be appeneded to the end of the list and the
     * @dev    non-enumerable mapping key value will be set to true.
     * 
     * @dev <h4>Postconditions:</h4>
     *      1. Addresses in from list that are not already present in to list are added to the to list.
     *      2. Emits an `AddedAccountToList` event for each address copied to the list.
     * 
     * @param  listType          The type of list addresses are being copied from and to.
     * @param  destinationListId The id of the list being copied to.
     * @param  ptrFromList       The storage pointer for the list being copied from.
     * @param  ptrToList         The storage pointer for the list being copied to.
     */
    function _copyAddressSet(
        uint8 listType,
        uint120 destinationListId,
        List storage ptrFromList,
        List storage ptrToList
    ) private {
        EnumerableSet.AddressSet storage ptrFromSet = ptrFromList.enumerableAccounts;
        EnumerableSet.AddressSet storage ptrToSet = ptrToList.enumerableAccounts;
        mapping (address => bool) storage ptrToNonEnumerableSet = ptrToList.nonEnumerableAccounts;
        uint256 sourceLength = ptrFromSet.length();
        address account;
        for (uint256 i = 0; i < sourceLength;) {
            account = ptrFromSet.at(i); 
            if (ptrToSet.add(account)) {
                emit AddedAccountToList(listType, destinationListId, account);
                ptrToNonEnumerableSet[account] = true;
            }

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Copies all codehashes in `ptrFromList` to `ptrToList`.
     * 
     * @dev    This function will copy all codehashes from one list to another list.
     * @dev    Note: If used to copy codehashes to an existing list the current list contents will not be
     * @dev    deleted before copying. New codehashes will be appeneded to the end of the list and the
     * @dev    non-enumerable mapping key value will be set to true.
     * 
     * @dev <h4>Postconditions:</h4>
     *      1. Codehashes in from list that are not already present in to list are added to the to list.
     *      2. Emits an `AddedCodeHashToList` event for each codehash copied to the list.
     * 
     * @param  listType          The type of list codehashes are being copied from and to.
     * @param  destinationListId The id of the list being copied to.
     * @param  ptrFromList       The storage pointer for the list being copied from.
     * @param  ptrToList         The storage pointer for the list being copied to.
     */
    function _copyBytes32Set(
        uint8 listType,
        uint120 destinationListId,
        List storage ptrFromList,
        List storage ptrToList
    ) private {
        EnumerableSet.Bytes32Set storage ptrFromSet = ptrFromList.enumerableCodehashes;
        EnumerableSet.Bytes32Set storage ptrToSet = ptrToList.enumerableCodehashes;
        mapping (bytes32 => bool) storage ptrToNonEnumerableSet = ptrToList.nonEnumerableCodehashes;
        uint256 sourceLength = ptrFromSet.length();
        bytes32 codehash;
        for (uint256 i = 0; i < sourceLength;) {
            codehash = ptrFromSet.at(i);
            if (ptrToSet.add(codehash)) {
                emit AddedCodeHashToList(listType, destinationListId, codehash);
                ptrToNonEnumerableSet[codehash] = true;
            }

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Adds one or more accounts to a list.
     */
    function _addAccountsToList(
        List storage list,
        uint8 listType,
        uint120 id,
        address[] memory accounts
    ) 
    internal
    onlyListOwner(id) {
        address account;
        for (uint256 i = 0; i < accounts.length;) {
            account = accounts[i];

            if (list.enumerableAccounts.add(account)) {
                emit AddedAccountToList(listType, id, account);
                list.nonEnumerableAccounts[account] = true;
            }

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Adds one or more codehashes to a list.
     */
    function _addCodeHashesToList(
        List storage list,
        uint8 listType,
        uint120 id,
        bytes32[] calldata codehashes
    ) 
    internal
    onlyListOwner(id) {
        bytes32 codehash;
        for (uint256 i = 0; i < codehashes.length;) {
            codehash = codehashes[i];

            if (list.enumerableCodehashes.add(codehash)) {
                emit AddedCodeHashToList(listType, id, codehash);
                list.nonEnumerableCodehashes[codehash] = true;
            }

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Removes one or more accounts from a list.
     */
    function _removeAccountsFromList(
        List storage list, 
        uint8 listType,
        uint120 id, 
        address[] memory accounts
    ) 
    internal 
    onlyListOwner(id) {
        address account;
        for (uint256 i = 0; i < accounts.length;) {
            account = accounts[i];
            if (list.enumerableAccounts.remove(account)) {
                emit RemovedAccountFromList(listType, id, account);
                delete list.nonEnumerableAccounts[account];
            }

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Removes one or more codehashes from a list.
     */
    function _removeCodeHashesFromList(
        List storage list, 
        uint8 listType, 
        uint120 id, 
        bytes32[] calldata codehashes
    ) 
    internal 
    onlyListOwner(id) {
        bytes32 codehash;
        for (uint256 i = 0; i < codehashes.length;) {
            codehash = codehashes[i];
            if (list.enumerableCodehashes.remove(codehash)) {
                emit RemovedCodeHashFromList(listType, id, codehash);
                delete list.nonEnumerableCodehashes[codehash];
            }

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Sets the owner of list `id` to `newOwner`.
     * 
     * @dev    Throws when the caller is not the owner of the list.
     * 
     * @dev    <h4>Postconditions:</h4>
     *         1. The owner of list `id` is set to `newOwner`.
     *         2. Emits a `ReassignedListOwnership` event.
     */
    function _reassignOwnershipOfList(uint120 id, address newOwner) private {
        _requireCallerOwnsList(id);
        listOwners[id] = newOwner;
        emit ReassignedListOwnership(id, newOwner);
    }

    /**
     * @notice Requires the caller to be the owner of list `id`.
     * 
     * @dev    Throws when the caller is not the owner of the list.
     */
    function _requireCallerOwnsList(uint120 id) private view {
        if (msg.sender != listOwners[id]) {
            revert CreatorTokenTransferValidator__CallerDoesNotOwnList();
        }
    }

    /**
     * @dev Internal function used to efficiently retrieve the code length of `account`.
     * 
     * @param account The address to get the deployed code length for.
     * 
     * @return length The length of deployed code at the address.
     */
    function _getCodeLengthAsm(address account) internal view returns (uint256 length) {
        assembly { length := extcodesize(account) }
    }

    /**
     * @dev Internal function used to efficiently retrieve the codehash of `account`.
     * 
     * @param account The address to get the deployed codehash for.
     * 
     * @return codehash The codehash of the deployed code at the address.
     */
    function _getCodeHashAsm(address account) internal view returns (bytes32 codehash) {
        assembly { codehash := extcodehash(account) }
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
        uint256 /*amount*/
    ) internal override returns (bool isError) {
        isError = SELECTOR_NO_ERROR != _validateTransfer(token, msg.sender, from, to, id);
    }

    /**
     * @notice Apply the collection transfer policy to a transfer operation of a creator token.
     *
     * @dev If the caller is self (Permit-C Processor) it means we have already applied operator validation in the 
     *      _beforeTransferFrom callback.  In this case, the security policy was already applied and the operator
     *      that used the Permit-C processor passed the security policy check and transfer can be safely allowed.
     *
     * @dev The order of checking whitelisted accounts, authorized operator check and whitelisted codehashes
     *      is very deliberate.  The order of operations is determined by the most frequently used settings that are
     *      expected in the wild.
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
    function _validateTransfer(
        address collection, 
        address caller, 
        address from, 
        address to,
        uint256 tokenId
    ) internal view returns (bytes4) {
        if (caller == address(this)) { 
            // If the caller is self (Permit-C Processor) it means we have already applied operator validation in the 
            // _beforeTransferFrom callback.  In this case, the security policy was already applied and the operator
            // that used the Permit-C processor passed the security policy check and transfer can be safely allowed.
            return SELECTOR_NO_ERROR;
        }

        CollectionSecurityPolicyV3 storage collectionSecurityPolicy = collectionSecurityPolicies[collection];

        uint120 listId = collectionSecurityPolicy.listId;

        (uint256 callerConstraints, uint256 receiverConstraints) = 
            transferSecurityPolicies(collectionSecurityPolicy.transferSecurityLevel);

        if (collectionSecurityPolicy.enableAccountFreezingMode) {
            AccountList storage frozenAccountList = frozenAccounts[collection];
            
            if (frozenAccountList.nonEnumerableAccounts[from]) {
                return CreatorTokenTransferValidator__SenderAccountIsFrozen.selector;
            }

            if (frozenAccountList.nonEnumerableAccounts[to]) {
                return CreatorTokenTransferValidator__ReceiverAccountIsFrozen.selector;
            }
        }

        if (callerConstraints == CALLER_CONSTRAINTS_SBT) {
            return CreatorTokenTransferValidator__TokenIsSoulbound.selector;
        }

        List storage whitelist = whitelists[listId];

        if (receiverConstraints == RECEIVER_CONSTRAINTS_NO_CODE) {
            if (_getCodeLengthAsm(to) > 0) {
                if (!whitelist.nonEnumerableAccounts[to]) {
                    if(!_callerAuthorized(collection, caller, tokenId)) {
                        if (!whitelist.nonEnumerableCodehashes[_getCodeHashAsm(to)]) {
                            return CreatorTokenTransferValidator__ReceiverMustNotHaveDeployedCode.selector;
                        }
                    }
                }
            }
        } else if (receiverConstraints == RECEIVER_CONSTRAINTS_EOA) {
            if (!isVerifiedEOA(to)) {
                if (!whitelist.nonEnumerableAccounts[to]) {
                    if(!_callerAuthorized(collection, caller, tokenId)) {
                        if (!whitelist.nonEnumerableCodehashes[_getCodeHashAsm(to)]) {
                            return CreatorTokenTransferValidator__ReceiverProofOfEOASignatureUnverified.selector;
                        }
                    }
                }
            }
        }

        if (caller == from) {
            if (callerConstraints != CALLER_CONSTRAINTS_OPERATOR_WHITELIST_DISABLE_OTC) {
                return SELECTOR_NO_ERROR;
            }
        }

        if (callerConstraints == CALLER_CONSTRAINTS_OPERATOR_BLACKLIST_ENABLE_OTC) {
            if(_callerAuthorized(collection, caller, tokenId)) {
                return SELECTOR_NO_ERROR;
            }

            List storage blacklist = blacklists[listId];
            if (blacklist.nonEnumerableAccounts[caller]) {
                return CreatorTokenTransferValidator__OperatorIsBlacklisted.selector;
            }

            if (blacklist.nonEnumerableCodehashes[_getCodeHashAsm(caller)]) {
                return CreatorTokenTransferValidator__OperatorIsBlacklisted.selector;
            }
        } else if (callerConstraints == CALLER_CONSTRAINTS_OPERATOR_WHITELIST_ENABLE_OTC) {
            if (whitelist.nonEnumerableAccounts[caller]) {
                return SELECTOR_NO_ERROR;
            }

            if( _callerAuthorized(collection, caller, tokenId)) {
                return SELECTOR_NO_ERROR;
            }

            if (whitelist.nonEnumerableCodehashes[_getCodeHashAsm(caller)]) {
                return SELECTOR_NO_ERROR;
            }

            return CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector;
        } else if (callerConstraints == CALLER_CONSTRAINTS_OPERATOR_WHITELIST_DISABLE_OTC) {
            mapping(address => bool) storage accountWhitelist = whitelist.nonEnumerableAccounts;

            if (accountWhitelist[caller]) {
                return SELECTOR_NO_ERROR;
            }

            if (accountWhitelist[from]) {
                return SELECTOR_NO_ERROR;
            }

            if(_callerAuthorized(collection, caller, tokenId)) {
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

    function _checkCollectionAllowsAuthorizerAndOperator(
        address collection, 
        address operator, 
        address authorizer
    ) internal view {
        CollectionSecurityPolicyV3 storage collectionSecurityPolicy = collectionSecurityPolicies[collection];

        if (!collectionSecurityPolicy.enableAuthorizationMode) {
            revert CreatorTokenTransferValidator__AuthorizationDisabledForCollection();
        }

        if (!collectionSecurityPolicy.authorizersCanSetWildcardOperators) {
            if (operator == WILDCARD_OPERATOR_ADDRESS) {
                revert CreatorTokenTransferValidator__WildcardOperatorsCannotBeAuthorizedForCollection();
            }
        }

        if (!authorizers[collectionSecurityPolicy.listId].nonEnumerableAccounts[authorizer]) {
            revert CreatorTokenTransferValidator__CallerMustBeAnAuthorizer();
        }
    }

    modifier whenAuthorizerAndOperatorEnabledForCollection(
        address collection, 
        address operator, 
        address authorizer
    ) {
        _checkCollectionAllowsAuthorizerAndOperator(collection, operator, authorizer);
        _;
    }

    function _setOperatorInTransientStorage(
        address operator,
        address collection, 
        uint256 tokenId
    ) internal whenAuthorizerAndOperatorEnabledForCollection(collection, operator, msg.sender) {
        _tstore(_getTransientOperatorSlot(collection), bytes32(uint256(uint160(operator))));
        _tstore(_getTransientOperatorSlot(collection, tokenId), bytes32(uint256(uint160(operator))));
    }

    function _callerAuthorized(
      address collection,
        address caller,
        uint256 tokenId
    ) internal view returns (bool) {
        return 
            _callerAuthorized(caller, _getTransientOperatorSlot(collection, tokenId)) ||
            _callerAuthorized(caller, _getTransientOperatorSlot(collection));
    }

    function _callerAuthorized(address caller, bytes32 slot) internal view returns (bool isAuthorized) {
        address authorizedOperator = address(uint160(uint256(_tload(slot))));
        isAuthorized = authorizedOperator == WILDCARD_OPERATOR_ADDRESS || authorizedOperator == caller;
    }

    /**
     * @dev Internal function used to compute the transient storage slot for the authorized operator of a collection.
     */
    function _getTransientOperatorSlot(
        address collection, 
        uint256 tokenId
    ) internal pure returns (bytes32 operatorSlot) {
        assembly {
            mstore(0x00, collection)
            mstore(0x20, tokenId)
            operatorSlot := keccak256(0x00, 0x40)
       }
    }

    function _getTransientOperatorSlot(address collection) internal pure returns (bytes32 operatorSlot) {
        return bytes32(uint256(uint160(collection)));
    }

    /**
     * @dev Internal function used to store a value in the specified transient storage slot.
     */
    function _tstore(bytes32 slot, bytes32 value) internal {
        assembly {
            tstore(slot, value)
        }
    }

    /**
     * @dev Internal function used to load a value from the specified transient storage slot.
     */
    function _tload(bytes32 slot) internal view returns (bytes32 value) {
        assembly {
            value := tload(slot)
        }
    }

    /**
     * @dev A gas efficient, and fallback-safe way to call the owner function on a token contract.
     *      This will get the owner if it exists - and when the function is unimplemented, the
     *      presence of a fallback function will not result in halted execution.
     */
    function _safeOwner(
        address tokenAddress
    ) internal view returns(address owner, bool isError) {
        assembly {
            function _callOwner(_tokenAddress) -> _owner, _isError {
                mstore(0x00, 0x8da5cb5b)
                if and(iszero(lt(returndatasize(), 0x20)), staticcall(gas(), _tokenAddress, 0x1C, 0x04, 0x00, 0x20)) {
                    _owner := mload(0x00)
                    leave
                }
                _isError := true
            }
            owner, isError := _callOwner(tokenAddress)
        }
    }
    
    /**
     * @dev A gas efficient, and fallback-safe way to call the hasRole function on a token contract.
     *      This will check if the account `hasRole` if `hasRole` exists - and when the function is unimplemented, the
     *      presence of a fallback function will not result in halted execution.
     */
    function _safeHasRole(
        address tokenAddress,
        bytes32 role,
        address account
    ) internal view returns(bool hasRole, bool isError) {
        assembly {
            function _callHasRole(_tokenAddress, _role, _account) -> _hasRole, _isError {
                let ptr := mload(0x40)
                mstore(0x40, add(ptr, 0x60))
                mstore(ptr, 0x91d14854)
                mstore(add(0x20, ptr), _role)
                mstore(add(0x40, ptr), _account)
                if and(iszero(lt(returndatasize(), 0x20)), staticcall(gas(), _tokenAddress, add(ptr, 0x1C), 0x44, 0x00, 0x20)) {
                    _hasRole := mload(0x00)
                    leave
                }
                _isError := true
            }
            hasRole, isError := _callHasRole(tokenAddress, role, account)
        }
    }

    function _asSingletonArray(address account) private pure returns (address[] memory array) {
        array = new address[](1);
        array[0] = account;
    }
}