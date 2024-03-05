// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./EOARegistry.sol";
import "../Constants.sol";
import "../interfaces/IOwnable.sol";
import "../interfaces/ICreatorTokenTransferValidator.sol";
import "../interfaces/ICreatorTokenTransferValidatorV3.sol";
import "@limitbreak/permit-c/PermitC.sol";
import "@openzeppelin/contracts/access/IAccessControl.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title  CreatorTokenTransferValidatorV3
 * @author Limit Break, Inc.
 * @notice The CreatorTokenTransferValidatorV3 contract is designed to provide a customizable and secure transfer 
 *         validation mechanism for NFT collections. This contract allows the owner of an NFT collection to configure 
 *         the transfer security level, blacklisted accounts and codehashes, whitelisted accounts and codehashes, and
 *         graylisted accounts and codehashes for each collection.
 *
 * @dev    <h4>Features</h4>
 *         - Transfer security levels: Provides different levels of transfer security, 
 *           from open transfers to completely restricted transfers.
 *         - Blacklist: Allows the owner of a collection to blacklist specific operator addresses or codehashes
 *           from executing transfers on behalf of others.
 *         - Whitelist: Allows the owner of a collection to whitelist specific operator addresses or codehashes
 *           permitted to execute transfers on behalf of others or send/receive tokens when otherwise disabled by 
 *           security policy.
 *         - Graylist: Allows the owner of a collection to enable graylisting contracts, that can perform 
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
contract CreatorTokenTransferValidatorV3 is EOARegistry, PermitC, ICreatorTokenTransferValidatorV3 {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // Custom Errors
    /// @dev Thrown when an array that cannot be zero length is supplied with zero length.
    error CreatorTokenTransferValidator__ArrayLengthCannotBeZero();

    /// @dev Thrown when attempting to set a list id that does not exist.
    error CreatorTokenTransferValidator__ListDoesNotExist();

    /// @dev Thrown when attempting to transfer the ownership of a list to the zero address.
    error CreatorTokenTransferValidator__ListOwnershipCannotBeTransferredToZeroAddress();

    /// @dev Thrown when attempting to call a function that requires the caller to be the list owner.
    error CreatorTokenTransferValidator__CallerDoesNotOwnList();

    /// @dev Thrown when validating a transfer for a collection using whitelists and the operator is not on the whitelist.
    error CreatorTokenTransferValidator__CallerMustBeWhitelisted();

    /// @dev Thrown when graylisting a transfer for a collection using graylists and the msg.sender is not in the graylist.
    error CreatorTokenTransferValidator__CallerMustBeGraylisted();

    /// @dev Thrown when attempting to call a function that requires owner or default admin role for a collection that the caller does not have.
    error CreatorTokenTransferValidator__CallerMustHaveElevatedPermissionsForSpecifiedNFT();

    /// @dev Thrown when setting the transfer security level to an invalid value.
    error CreatorTokenTransferValidator__InvalidTransferSecurityLevel();

    /// @dev Thrown when validating a transfer for a collection using blacklists and the operator is on the blacklist.
    error CreatorTokenTransferValidator__OperatorIsBlacklisted();

    /// @dev Thrown when validating a transfer for a collection that does not allow receiver to have code and the receiver has code.
    error CreatorTokenTransferValidator__ReceiverMustNotHaveDeployedCode();

    /// @dev Thrown when validating a transfer for a collection that requires receivers be verified EOAs and the receiver is not verified.
    error CreatorTokenTransferValidator__ReceiverProofOfEOASignatureUnverified();

    /// @dev Thrown when attempting to add the zero address to a whitelist or blacklist.
    error CreatorTokenTransferValidator__ZeroAddressNotAllowed();

    /// @dev Thrown when attempting to add the zero code hash to a whitelist or blacklist.
    error CreatorTokenTransferValidator__ZeroCodeHashNotAllowed();

    /// @dev Thrown when attempting to set a graylist operator when graylisting is disabled.
    error CreatorTokenTransferValidator__GraylistingDisabledForCollection();

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

    // Immutable lookup tables
    uint256 private immutable _callerConstraintsLookup;
    uint256 private immutable _receiverConstraintsLookup;
    
    // Constants
    /// @dev The default admin role value for contracts that implement access control.
    bytes32 private constant DEFAULT_ACCESS_CONTROL_ADMIN_ROLE = 0x00;
    /// @dev Value representing a zero value code hash.
    bytes32 private constant CODEHASH_ZERO = 0x0000000000000000000000000000000000000000000000000000000000000000;

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

    /// @dev Mapping of list ids to graylist settings
    mapping (uint120 => List) internal graylists;

    constructor(
        address defaultOwner,
        string memory name,
        string memory version
    ) 
    EOARegistry() 
    PermitC(name, version) {
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
            | (CALLER_CONSTRAINTS_OPERATOR_WHITELIST_DISABLE_OTC << (TRANSFER_SECURITY_LEVEL_EIGHT << 3));

        _receiverConstraintsLookup = 
            (RECEIVER_CONSTRAINTS_NONE << (TRANSFER_SECURITY_LEVEL_RECOMMENDED << 3))
            | (RECEIVER_CONSTRAINTS_NONE << (TRANSFER_SECURITY_LEVEL_ONE << 3))
            | (RECEIVER_CONSTRAINTS_NONE << (TRANSFER_SECURITY_LEVEL_TWO << 3))
            | (RECEIVER_CONSTRAINTS_NONE << (TRANSFER_SECURITY_LEVEL_THREE << 3))
            | (RECEIVER_CONSTRAINTS_NONE << (TRANSFER_SECURITY_LEVEL_FOUR << 3))
            | (RECEIVER_CONSTRAINTS_NO_CODE << (TRANSFER_SECURITY_LEVEL_FIVE << 3))
            | (RECEIVER_CONSTRAINTS_EOA << (TRANSFER_SECURITY_LEVEL_SIX << 3))
            | (RECEIVER_CONSTRAINTS_NO_CODE << (TRANSFER_SECURITY_LEVEL_SEVEN << 3))
            | (RECEIVER_CONSTRAINTS_EOA << (TRANSFER_SECURITY_LEVEL_EIGHT << 3));
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

    /**
     * @dev This modifier reverts a transaction if the supplied array has a zero length.
     * @dev Throws when the array parameter has a zero length.
     */
    modifier notZero(uint256 value) {
        _requireNotZero(value);
        _;
    }

    /*************************************************************************/
    /*                          APPLY TRANSFER POLICIES                      */
    /*************************************************************************/

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
        bytes4 errorSelector = _applyCollectionTransferPolicy(caller, _msgSender(), from, to);
        if (errorSelector != SELECTOR_NO_ERROR) {
            _revertCustomErrorSelectorAsm(errorSelector);
        }
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

    function beforeGraylistedTransfer(address operator, address[] calldata tokenAddresses) external {
        _setOperatorInTransientStorage(operator, tokenAddresses);
    }

    function afterGraylistedTransfer(address[] calldata tokenAddresses) external {
        _setOperatorInTransientStorage(address(0), tokenAddresses);
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
     * @param name The name of the new list.
     * @return     The id of the new list.
     */
    function createList(string calldata name) public override returns (uint120) {
        uint120 id = ++lastListId;

        listOwners[id] = _msgSender();

        emit CreatedList(id, name);
        emit ReassignedListOwnership(id, _msgSender());

        return id;
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
     * @param name         The name of the new list.
     * @param sourceListId The id of the source list to copy from.
     * @return             The id of the new list.
     */
    function createListCopy(string calldata name, uint120 sourceListId) external override returns (uint120) {
        uint120 id = ++lastListId;

        unchecked {
            if (sourceListId > id - 1) {
                revert CreatorTokenTransferValidator__ListDoesNotExist();
            }
        }

        listOwners[id] = _msgSender();

        emit CreatedList(id, name);
        emit ReassignedListOwnership(id, _msgSender());

        List storage sourceBlacklist = blacklists[sourceListId];
        List storage sourceWhitelist = whitelists[sourceListId];
        List storage sourceGraylist = graylists[sourceListId];
        List storage targetBlacklist = blacklists[id];
        List storage targetWhitelist = whitelists[id];
        List storage targetGraylist = graylists[id];

        _copyAddressSet(LIST_TYPE_BLACKLIST, id, sourceBlacklist, targetBlacklist);
        _copyBytes32Set(LIST_TYPE_BLACKLIST, id, sourceBlacklist, targetBlacklist);
        _copyAddressSet(LIST_TYPE_WHITELIST, id, sourceWhitelist, targetWhitelist);
        _copyBytes32Set(LIST_TYPE_WHITELIST, id, sourceWhitelist, targetWhitelist);
        _copyAddressSet(LIST_TYPE_GRAYLIST, id, sourceGraylist, targetGraylist);
        _copyBytes32Set(LIST_TYPE_GRAYLIST, id, sourceGraylist, targetGraylist);

        return id;
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
    function reassignOwnershipOfList(uint120 id, address newOwner) public override {
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
    function renounceOwnershipOfList(uint120 id) public override {
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
        bool enableGraylisting) external override {

        if (level > TRANSFER_SECURITY_LEVEL_EIGHT) {
            revert CreatorTokenTransferValidator__InvalidTransferSecurityLevel();
        }

        _requireCallerIsNFTOrContractOwnerOrAdmin(collection);
        collectionSecurityPolicies[collection].transferSecurityLevel = level;
        collectionSecurityPolicies[collection].enableGraylisting = enableGraylisting;
        emit SetTransferSecurityLevel(collection, level);
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
    function applyListToCollection(address collection, uint120 id) public override {
        _requireCallerIsNFTOrContractOwnerOrAdmin(collection);

        if (id > lastListId) {
            revert CreatorTokenTransferValidator__ListDoesNotExist();
        }

        collectionSecurityPolicies[collection].listId = id;
        emit AppliedListToCollection(collection, id);
    }

    /**
     * @notice Get the security policy of the specified collection.
     * @param collection The address of the collection.
     * @return           The security policy of the specified collection, which includes:
     *                   Transfer security level, operator whitelist id, permitted contract receiver allowlist id
     */
    function getCollectionSecurityPolicyV3(address collection) 
        external view override returns (CollectionSecurityPolicyV3 memory) {
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
        address[] calldata accounts
    ) external override {
        _addAccountsToList(blacklists[id], LIST_TYPE_BLACKLIST, id, accounts);
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
        address[] calldata accounts
    ) external override {
        _addAccountsToList(whitelists[id], LIST_TYPE_WHITELIST, id, accounts);
    }

    /**
     * @notice Adds one or more accounts to a graylist.
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
    function addAccountsToGraylist(
        uint120 id, 
        address[] calldata accounts
    ) external override {
        _addAccountsToList(graylists[id], LIST_TYPE_GRAYLIST, id, accounts);
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
    ) external override {
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
    ) external override {
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
        address[] calldata accounts
    ) external override {
        _removeAccountsFromList(blacklists[id], LIST_TYPE_BLACKLIST, id, accounts);
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
        address[] calldata accounts
    ) external override {
        _removeAccountsFromList(whitelists[id], LIST_TYPE_WHITELIST, id, accounts);
    }

    /**
     * @notice Removes one or more accounts from a graylist.
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
    function removeAccountsFromGraylist(
        uint120 id, 
        address[] calldata accounts
    ) external override {
        _removeAccountsFromList(graylists[id], LIST_TYPE_GRAYLIST, id, accounts);
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
    ) external override {
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
    ) external override {
        _removeCodeHashesFromList(whitelists[id], LIST_TYPE_WHITELIST, id, codehashes);
    }

    /**
     * @notice Get blacklisted accounts by list id.
     * @param  id The id of the list.
     * @return An array of blacklisted accounts.
     */
    function getBlacklistedAccounts(uint120 id) public view override returns (address[] memory) {
        return blacklists[id].enumerableAccounts.values();
    }

    /**
     * @notice Get whitelisted accounts by list id.
     * @param  id The id of the list.
     * @return An array of whitelisted accounts.
     */
    function getWhitelistedAccounts(uint120 id) public view override returns (address[] memory) {
        return whitelists[id].enumerableAccounts.values();
    }

    /**
     * @notice Get graylisted accounts by list id.
     * @param  id The id of the list.
     * @return An array of graylisted accounts.
     */
    function getGraylistedAccounts(uint120 id) public view override returns (address[] memory) {
        return graylists[id].enumerableAccounts.values();
    }

    /**
     * @notice Get blacklisted codehashes by list id.
     * @param id The id of the list.
     * @return   An array of blacklisted codehashes.
     */
    function getBlacklistedCodeHashes(uint120 id) public view override returns (bytes32[] memory) {
        return blacklists[id].enumerableCodehashes.values();
    }

    /**
     * @notice Get whitelisted codehashes by list id.
     * @param id The id of the list.
     * @return   An array of whitelisted codehashes.
     */
    function getWhitelistedCodeHashes(uint120 id) public view override returns (bytes32[] memory) {
        return whitelists[id].enumerableCodehashes.values();
    }

    /**
     * @notice Check if an account is blacklisted in a specified list.
     * @param id       The id of the list.
     * @param account  The address of the account to check.
     * @return         True if the account is blacklisted in the specified list, false otherwise.
     */
    function isAccountBlacklisted(uint120 id, address account) public view override returns (bool) {
        return blacklists[id].nonEnumerableAccounts[account];
    }

    /**
     * @notice Check if an account is whitelisted in a specified list.
     * @param id       The id of the list.
     * @param account  The address of the account to check.
     * @return         True if the account is whitelisted in the specified list, false otherwise.
     */
    function isAccountWhitelisted(uint120 id, address account) public view override returns (bool) {
        return whitelists[id].nonEnumerableAccounts[account];
    }

    /**
     * @notice Check if an account is graylisted in a specified list.
     * @param id       The id of the list.
     * @param account  The address of the account to check.
     * @return         True if the account is graylisted in the specified list, false otherwise.
     */
    function isAccountGraylisted(uint120 id, address account) public view override returns (bool) {
        return graylists[id].nonEnumerableAccounts[account];
    }

    /**
     * @notice Check if a codehash is blacklisted in a specified list.
     * @param id       The id of the list.
     * @param codehash  The codehash to check.
     * @return         True if the codehash is blacklisted in the specified list, false otherwise.
     */
    function isCodeHashBlacklisted(uint120 id, bytes32 codehash) public view override returns (bool) {
        return codehash == CODEHASH_ZERO ? false : blacklists[id].nonEnumerableCodehashes[codehash];
    }

    /**
     * @notice Check if a codehash is whitelisted in a specified list.
     * @param id       The id of the list.
     * @param codehash  The codehash to check.
     * @return         True if the codehash is whitelisted in the specified list, false otherwise.
     */
    function isCodeHashWhitelisted(uint120 id, bytes32 codehash) public view override returns (bool) {
        return codehash == CODEHASH_ZERO ? false : whitelists[id].nonEnumerableCodehashes[codehash];
    }

    /**
     * @notice Get blacklisted accounts by collection.
     * @param collection The address of the collection.
     * @return           An array of blacklisted accounts.
     */
    function getBlacklistedAccountsByCollection(address collection) external view override returns (address[] memory) {
        return getBlacklistedAccounts(collectionSecurityPolicies[collection].listId);
    }

    /**
     * @notice Get whitelisted accounts by collection.
     * @param collection The address of the collection.
     * @return           An array of whitelisted accounts.
     */
    function getWhitelistedAccountsByCollection(address collection) external view override returns (address[] memory) {
        return getWhitelistedAccounts(collectionSecurityPolicies[collection].listId);
    }

    /**
     * @notice Get graylisted accounts by collection.
     * @param collection The address of the collection.
     * @return           An array of graylisted accounts.
     */
    function getGraylistedAccountsByCollection(address collection) external view override returns (address[] memory) {
        return getGraylistedAccounts(collectionSecurityPolicies[collection].listId);
    }

    /**
     * @notice Get blacklisted codehashes by collection.
     * @param collection The address of the collection.
     * @return           An array of blacklisted codehashes.
     */
    function getBlacklistedCodeHashesByCollection(address collection) external view override returns (bytes32[] memory) {
        return getBlacklistedCodeHashes(collectionSecurityPolicies[collection].listId);
    }

    /**
     * @notice Get whitelisted codehashes by collection.
     * @param collection The address of the collection.
     * @return           An array of whitelisted codehashes.
     */
    function getWhitelistedCodeHashesByCollection(address collection) external view override returns (bytes32[] memory) {
        return getWhitelistedCodeHashes(collectionSecurityPolicies[collection].listId);
    }

    /**
     * @notice Check if an account is blacklisted by a specified collection.
     * @param collection The address of the collection.
     * @param account    The address of the account to check.
     * @return           True if the account is blacklisted by the specified collection, false otherwise.
     */
    function isAccountBlacklistedByCollection(address collection, address account) external view override returns (bool) {
        return isAccountBlacklisted(collectionSecurityPolicies[collection].listId, account);
    }

    /**
     * @notice Check if an account is whitelisted by a specified collection.
     * @param collection The address of the collection.
     * @param account    The address of the account to check.
     * @return           True if the account is whitelisted by the specified collection, false otherwise.
     */
    function isAccountWhitelistedByCollection(address collection, address account) external view override returns (bool) {
        return isAccountWhitelisted(collectionSecurityPolicies[collection].listId, account);
    }

    /**
     * @notice Check if an account is graylisted by a specified collection.
     * @param collection The address of the collection.
     * @param account    The address of the account to check.
     * @return           True if the account is graylisted by the specified collection, false otherwise.
     */
    function isAccountGraylistedByCollection(address collection, address account) external view override returns (bool) {
        return isAccountGraylisted(collectionSecurityPolicies[collection].listId, account);
    }

    /**
     * @notice Check if a codehash is blacklisted by a specified collection.
     * @param collection The address of the collection.
     * @param codehash   The codehash to check.
     * @return           True if the codehash is blacklisted by the specified collection, false otherwise.
     */
    function isCodeHashBlacklistedByCollection(address collection, bytes32 codehash) external view override returns (bool) {
        return isCodeHashBlacklisted(collectionSecurityPolicies[collection].listId, codehash);
    }

    /**
     * @notice Check if a codehash is whitelisted by a specified collection.
     * @param collection The address of the collection.
     * @param codehash   The codehash to check.
     * @return           True if the codehash is whitelisted by the specified collection, false otherwise.
     */
    function isCodeHashWhitelistedByCollection(address collection, bytes32 codehash) external view override returns (bool) {
        return isCodeHashWhitelisted(collectionSecurityPolicies[collection].listId, codehash);
    }

    /// @notice ERC-165 Interface Support
    function supportsInterface(bytes4 interfaceId) public view virtual override(EOARegistry, IERC165) returns (bool) {
        return
            interfaceId == type(ITransferValidator).interfaceId ||
            interfaceId == type(ITransferSecurityRegistry).interfaceId ||
            interfaceId == type(ITransferSecurityRegistryV3).interfaceId ||
            interfaceId == type(ICreatorTokenTransferValidator).interfaceId ||
            interfaceId == type(ICreatorTokenTransferValidatorV3).interfaceId ||
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
        if(_getCodeLengthAsm(tokenAddress) > 0) {
            callerHasPermissions = _msgSender() == tokenAddress;
            if(!callerHasPermissions) {

                try IOwnable(tokenAddress).owner() returns (address contractOwner) {
                    callerHasPermissions = _msgSender() == contractOwner;
                } catch {}

                if(!callerHasPermissions) {
                    try IAccessControl(tokenAddress).hasRole(DEFAULT_ACCESS_CONTROL_ADMIN_ROLE, _msgSender()) 
                        returns (bool callerIsContractAdmin) {
                        callerHasPermissions = callerIsContractAdmin;
                    } catch {}
                }
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
        address[] calldata accounts
    ) 
    internal
    onlyListOwner(id) 
    notZero(accounts.length) {
        address account;
        for (uint256 i = 0; i < accounts.length;) {
            account = accounts[i];

            if (account == address(0)) {
                revert CreatorTokenTransferValidator__ZeroAddressNotAllowed();
            }

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
    onlyListOwner(id) 
    notZero(codehashes.length) {
        bytes32 codehash;
        for (uint256 i = 0; i < codehashes.length;) {
            codehash = codehashes[i];

            if (codehash == CODEHASH_ZERO) {
                revert CreatorTokenTransferValidator__ZeroCodeHashNotAllowed();
            }

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
        address[] calldata accounts
    ) 
    internal 
    onlyListOwner(id) 
    notZero(accounts.length) {
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
    onlyListOwner(id) 
    notZero(codehashes.length) {
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
        if (_msgSender() != listOwners[id]) {
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
     * @dev Reverts if `value` is zero.
     */
    function _requireNotZero(uint256 value) internal pure {
        if (value == 0) {
            revert CreatorTokenTransferValidator__ArrayLengthCannotBeZero();
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
        isError = _applyCollectionTransferPolicy(_msgSender(), token, from, to) != SELECTOR_NO_ERROR;
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
    function _applyCollectionTransferPolicy(
        address caller, 
        address collection, 
        address from, 
        address to
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

        List storage whitelist = whitelists[listId];

        if (receiverConstraints == RECEIVER_CONSTRAINTS_NO_CODE) {
            if (_getCodeLengthAsm(to) > 0) {
                if (!whitelist.nonEnumerableAccounts[to]) {
                    if (!whitelist.nonEnumerableCodehashes[_getCodeHashAsm(to)]) {
                        if(_callerAllowedByGraylist(collectionSecurityPolicy.enableGraylisting, caller, collection)) {
                            return SELECTOR_NO_ERROR;
                        }

                        return CreatorTokenTransferValidator__ReceiverMustNotHaveDeployedCode.selector;
                    }
                }
            }
        } else if (receiverConstraints == RECEIVER_CONSTRAINTS_EOA) {
            if (!isVerifiedEOA(to)) {
                if (!whitelist.nonEnumerableAccounts[to]) {
                    if (!whitelist.nonEnumerableCodehashes[_getCodeHashAsm(to)]) {
                        if(_callerAllowedByGraylist(collectionSecurityPolicy.enableGraylisting, caller, collection)) {
                            return SELECTOR_NO_ERROR;
                        }

                        return CreatorTokenTransferValidator__ReceiverProofOfEOASignatureUnverified.selector;
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
            List storage blacklist = blacklists[listId];
            if (blacklist.nonEnumerableAccounts[caller]) {
                if(_callerAllowedByGraylist(collectionSecurityPolicy.enableGraylisting, caller, collection)) {
                    return SELECTOR_NO_ERROR;
                }

                return CreatorTokenTransferValidator__OperatorIsBlacklisted.selector;
            }

            if (blacklist.nonEnumerableCodehashes[_getCodeHashAsm(caller)]) {
                if(_callerAllowedByGraylist(collectionSecurityPolicy.enableGraylisting, caller, collection)) {
                    return SELECTOR_NO_ERROR;
                }

                return CreatorTokenTransferValidator__OperatorIsBlacklisted.selector;
            }
        } else if (callerConstraints == CALLER_CONSTRAINTS_OPERATOR_WHITELIST_ENABLE_OTC) {
            if (whitelist.nonEnumerableAccounts[caller]) {
                return SELECTOR_NO_ERROR;
            }

            if (whitelist.nonEnumerableCodehashes[_getCodeHashAsm(caller)]) {
                return SELECTOR_NO_ERROR;
            }

            if(_callerAllowedByGraylist(collectionSecurityPolicy.enableGraylisting, caller, collection)) {
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

            mapping(bytes32 => bool) storage codehashWhitelist = whitelist.nonEnumerableCodehashes;

            if (codehashWhitelist[_getCodeHashAsm(caller)]) {
                return SELECTOR_NO_ERROR;
            }

            if (codehashWhitelist[_getCodeHashAsm(from)]) {
                return SELECTOR_NO_ERROR;
            }

            if(_callerAllowedByGraylist(collectionSecurityPolicy.enableGraylisting, caller, collection)) {
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

    /**
     * @dev Internal function used to set the operator in transient storage for a collection when called by graylisted
     *      account.
     */
    function _setOperatorInTransientStorage(address operator, address[] calldata tokenAddresses) internal {
        address collection;
        for (uint256 i = 0; i < tokenAddresses.length;) {
            collection = tokenAddresses[i];

            CollectionSecurityPolicyV3 storage collectionSecurityPolicy = collectionSecurityPolicies[collection];

            if (!graylists[collectionSecurityPolicy.listId].enumerableAccounts.contains(_msgSender())) {
                revert CreatorTokenTransferValidator__CallerMustBeGraylisted();
            }

            if (!collectionSecurityPolicy.enableGraylisting) {
                revert CreatorTokenTransferValidator__GraylistingDisabledForCollection();
            }

            _tstore(
                _getSlotTransientOperatorForCollection(collection), 
                _packAddressAsBytes32(operator)
            );

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @dev Internal function used to check if the caller is allowed by the graylist for a collection.
     */
    function _callerAllowedByGraylist(
        bool enableGraylisting, 
        address caller, 
        address collection
    ) internal view returns (bool) {
        return
            enableGraylisting && 
            _unpackAddressFromBytes32(_tload(_getSlotTransientOperatorForCollection(collection))) == caller;
    }

    /**
     * @dev Internal function used to compute the transient storage slot for the graylisted operator of a collection.
     */
    function _getSlotTransientOperatorForCollection(address collection) internal pure returns (bytes32) {
        return _packAddressAsBytes32(collection);
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
     * @dev Internal function used convert an address to a bytes32 for transient storage.
     */
    function _packAddressAsBytes32(address addr) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(addr)));
    }

    /**
     * @dev Internal function used convert a bytes32 to an address when loaded from transient storage.
     */
    function _unpackAddressFromBytes32(bytes32 addr) internal pure returns (address) {
        return address(uint160(uint256(addr)));
    }
}