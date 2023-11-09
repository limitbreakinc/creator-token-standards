// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./EOARegistry.sol";
import "../interfaces/IOwnable.sol";
import "../interfaces/ICreatorTokenTransferValidator.sol";
import "../interfaces/ICreatorTokenTransferValidatorV2.sol";
import "@openzeppelin/contracts/access/IAccessControl.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title  CreatorTokenTransferValidatorV2
 * @author Limit Break, Inc.
 * @notice The CreatorTokenTransferValidatorV2 contract is designed to provide a customizable and secure transfer 
 *         validation mechanism for NFT collections. This contract allows the owner of an NFT collection to configure 
 *         the transfer security level, blacklisted accounts and codehashes and whitelisted accounts and codehashes 
 *         for each collection.
 *
 * @dev    <h4>Features</h4>
 *         - Transfer security levels: Provides different levels of transfer security, 
 *           from open transfers to completely restricted transfers.
 *         - Blacklist: Allows the owner of a collection to blacklist specific operator addresses or codehashes
 *           from executing transfers on behalf of others.
 *         - Whitelist: Allows the owner of a collection to whitelist specific operator addresses or codehashes
 *           permitted to execute transfers on behalf of others or send/receive tokens when otherwise disabled by 
 *           security policy.
 *
 * @dev    <h4>Benefits</h4>
 *         - Enhanced security: Allows creators to have more control over their NFT collections, ensuring the safety 
 *           and integrity of their assets.
 *         - Flexibility: Provides collection owners the ability to customize transfer rules as per their requirements.
 *         - Compliance: Facilitates compliance with regulations by enabling creators to restrict transfers based on 
 *           specific criteria.
 *
 * @dev    <h4>Intended Usage</h4>
 *         - The CreatorTokenTransferValidatorV2 contract is intended to be used by NFT collection owners to manage and 
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
 *          - Recommended: Recommended defaults are same as Level 2 (Whitelisting with OTC Enabled).
 *          - Level 0: No transfer restrictions.
 *            - Caller Constraints: None
 *            - Receiver Constraints: None
 *          - Level 1: Only non-blacklisted operators can initiate transfers, over-the-counter (OTC) trading enabled.
 *            - Caller Constraints: OperatorBlacklistEnableOTC
 *            - Receiver Constraints: None
 *          - Level 2: Only whitelisted accounts can initiate transfers, over-the-counter (OTC) trading enabled.
 *            - Caller Constraints: OperatorWhitelistEnableOTC
 *            - Receiver Constraints: None
 *          - Level 3: Only whitelisted accounts can initiate transfers, over-the-counter (OTC) trading disabled.
 *            - Caller Constraints: OperatorWhitelistDisableOTC
 *            - Receiver Constraints: None
 *          - Level 4: Only whitelisted accounts can initiate transfers, over-the-counter (OTC) trading enabled. 
 *                     Transfers to contracts with code are not allowed, unless present on the whitelist.
 *            - Caller Constraints: OperatorWhitelistEnableOTC
 *            - Receiver Constraints: NoCode
 *          - Level 5: Only whitelisted accounts can initiate transfers, over-the-counter (OTC) trading enabled. 
 *                     Transfers are allowed only to Externally Owned Accounts (EOAs), unless present on the whitelist.
 *            - Caller Constraints: OperatorWhitelistEnableOTC
 *            - Receiver Constraints: EOA
 *          - Level 6: Only whitelisted accounts can initiate transfers, over-the-counter (OTC) trading disabled. 
 *                     Transfers to contracts with code are not allowed, unless present on the whitelist.
 *            - Caller Constraints: OperatorWhitelistDisableOTC
 *            - Receiver Constraints: NoCode
 *          - Level 7: Only whitelisted accounts can initiate transfers, over-the-counter (OTC) trading disabled. 
 *                     Transfers are allowed only to Externally Owned Accounts (EOAs), unless present on the whitelist.
 *            - Caller Constraints: OperatorWhitelistDisableOTC
 *            - Receiver Constraints: EOA
 */
contract CreatorTokenTransferValidatorV2 is EOARegistry, ICreatorTokenTransferValidatorV2 {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    error CreatorTokenTransferValidator__ArrayLengthCannotBeZero();
    error CreatorTokenTransferValidator__ListDoesNotExist();
    error CreatorTokenTransferValidator__ListOwnershipCannotBeTransferredToZeroAddress();
    error CreatorTokenTransferValidator__CallerDoesNotOwnList();
    error CreatorTokenTransferValidator__CallerMustBeWhitelisted();
    error CreatorTokenTransferValidator__CallerMustHaveElevatedPermissionsForSpecifiedNFT();
    error CreatorTokenTransferValidator__OperatorIsBlacklisted();
    error CreatorTokenTransferValidator__ReceiverMustNotHaveDeployedCode();
    error CreatorTokenTransferValidator__ReceiverProofOfEOASignatureUnverified();
    error CreatorTokenTransferValidator__ZeroCodeHashNotAllowed();
    
    bytes32 private constant DEFAULT_ACCESS_CONTROL_ADMIN_ROLE = 0x00;
    bytes32 private constant CODEHASH_ZERO = 0x0000000000000000000000000000000000000000000000000000000000000000;
    TransferSecurityLevels public constant DEFAULT_TRANSFER_SECURITY_LEVEL = TransferSecurityLevels.Zero;

    uint120 private lastListId;

    mapping (TransferSecurityLevels => TransferSecurityPolicy) public transferSecurityPolicies;
    mapping (address => CollectionSecurityPolicyV2) private collectionSecurityPolicies;
    mapping (uint120 => address) public listOwners;
    mapping (uint120 => EnumerableSet.AddressSet) private blacklists;
    mapping (uint120 => EnumerableSet.Bytes32Set) private codehashBlacklists;
    mapping (uint120 => EnumerableSet.AddressSet) private whitelists;
    mapping (uint120 => EnumerableSet.Bytes32Set) private codehashWhitelists;

    constructor(address defaultOwner) EOARegistry() {
        transferSecurityPolicies[TransferSecurityLevels.Recommended] = TransferSecurityPolicy({
            callerConstraints: CallerConstraints.OperatorWhitelistEnableOTC,
            receiverConstraints: ReceiverConstraints.None
        });

        transferSecurityPolicies[TransferSecurityLevels.Zero] = TransferSecurityPolicy({
            callerConstraints: CallerConstraints.None,
            receiverConstraints: ReceiverConstraints.None
        });

        transferSecurityPolicies[TransferSecurityLevels.One] = TransferSecurityPolicy({
            callerConstraints: CallerConstraints.OperatorBlacklistEnableOTC,
            receiverConstraints: ReceiverConstraints.None
        });

        transferSecurityPolicies[TransferSecurityLevels.Two] = TransferSecurityPolicy({
            callerConstraints: CallerConstraints.OperatorWhitelistEnableOTC,
            receiverConstraints: ReceiverConstraints.None
        });

        transferSecurityPolicies[TransferSecurityLevels.Three] = TransferSecurityPolicy({
            callerConstraints: CallerConstraints.OperatorWhitelistDisableOTC,
            receiverConstraints: ReceiverConstraints.None
        });

        transferSecurityPolicies[TransferSecurityLevels.Four] = TransferSecurityPolicy({
            callerConstraints: CallerConstraints.OperatorWhitelistEnableOTC,
            receiverConstraints: ReceiverConstraints.NoCode
        });

        transferSecurityPolicies[TransferSecurityLevels.Five] = TransferSecurityPolicy({
            callerConstraints: CallerConstraints.OperatorWhitelistEnableOTC,
            receiverConstraints: ReceiverConstraints.EOA
        });

        transferSecurityPolicies[TransferSecurityLevels.Six] = TransferSecurityPolicy({
            callerConstraints: CallerConstraints.OperatorWhitelistDisableOTC,
            receiverConstraints: ReceiverConstraints.NoCode
        });

        transferSecurityPolicies[TransferSecurityLevels.Seven] = TransferSecurityPolicy({
            callerConstraints: CallerConstraints.OperatorWhitelistDisableOTC,
            receiverConstraints: ReceiverConstraints.EOA
        });

        uint120 id = 0;

        listOwners[id] = defaultOwner;

        emit CreatedList(id, "DEFAULT LIST");
        emit ReassignedListOwnership(id, defaultOwner);
    }

    modifier onlyListOwner(uint120 id) {
        _requireCallerOwnsList(id);
        _;
    }

    modifier notZero(uint256 value) {
        if (value == 0) {
            revert CreatorTokenTransferValidator__ArrayLengthCannotBeZero();
        }
        _;
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
    function applyCollectionTransferPolicy(address caller, address from, address to) external view override {
        address collection = _msgSender();
        CollectionSecurityPolicyV2 memory collectionSecurityPolicy = collectionSecurityPolicies[collection];
        TransferSecurityPolicy memory transferSecurityPolicy = 
            transferSecurityPolicies[collectionSecurityPolicy.transferSecurityLevel];

        if (transferSecurityPolicy.receiverConstraints == ReceiverConstraints.NoCode) {
            if (to.code.length > 0) {
                if (!_isAccountOrCodeHashWhitelisted(collectionSecurityPolicy.listId, to)) {
                    revert CreatorTokenTransferValidator__ReceiverMustNotHaveDeployedCode();
                }
            }
        } else if (transferSecurityPolicy.receiverConstraints == ReceiverConstraints.EOA) {
            if (!isVerifiedEOA(to)) {
                if (!_isAccountOrCodeHashWhitelisted(collectionSecurityPolicy.listId, to)) {
                    revert CreatorTokenTransferValidator__ReceiverProofOfEOASignatureUnverified();
                }
            }
        }

        if (transferSecurityPolicy.callerConstraints == CallerConstraints.OperatorBlacklistEnableOTC) {
            if (caller == from) {
                return;
            } else if (_isAccountOrCodeHashBlacklisted(collectionSecurityPolicy.listId, caller)) {
                revert CreatorTokenTransferValidator__OperatorIsBlacklisted();
            }
        } else if (transferSecurityPolicy.callerConstraints == CallerConstraints.OperatorWhitelistEnableOTC) {
            if (caller == from) {
                return;
            } else if (!_isAccountOrCodeHashWhitelisted(collectionSecurityPolicy.listId, caller)) {
                revert CreatorTokenTransferValidator__CallerMustBeWhitelisted();
            }
        } else if (transferSecurityPolicy.callerConstraints == CallerConstraints.OperatorWhitelistDisableOTC) {
            if (!_isAccountOrCodeHashWhitelisted(collectionSecurityPolicy.listId, caller) &&
                !_isAccountOrCodeHashWhitelisted(collectionSecurityPolicy.listId, from)) {
                revert CreatorTokenTransferValidator__CallerMustBeWhitelisted();
            }
        }
    }

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

        listOwners[id] = _msgSender();

        emit CreatedList(id, name);
        emit ReassignedListOwnership(id, _msgSender());

        _copyAddressSet(ListTypes.Blacklist, id, blacklists[sourceListId], blacklists[id]);
        _copyBytes32Set(ListTypes.Blacklist, id, codehashBlacklists[sourceListId], codehashBlacklists[id]);
        _copyAddressSet(ListTypes.Whitelist, id, whitelists[sourceListId], whitelists[id]);
        _copyBytes32Set(ListTypes.Whitelist, id, codehashWhitelists[sourceListId], codehashWhitelists[id]);

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
        TransferSecurityLevels level) external override {
        _requireCallerIsNFTOrContractOwnerOrAdmin(collection);
        collectionSecurityPolicies[collection].transferSecurityLevel = level;
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
    function getCollectionSecurityPolicyV2(address collection) 
        external view override returns (CollectionSecurityPolicyV2 memory) {
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
    ) external override 
    onlyListOwner(id) 
    notZero(accounts.length) {
        EnumerableSet.AddressSet storage blacklist = blacklists[id];
        address account;
        for (uint256 i = 0; i < accounts.length;) {
            account = accounts[i];
            if (blacklist.add(account)) {
                emit AddedAccountToList(ListTypes.Blacklist, id, account);
            }

            unchecked {
                ++i;
            }
        }
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
    ) external override 
    onlyListOwner(id) 
    notZero(accounts.length) {
        EnumerableSet.AddressSet storage whitelist = whitelists[id];
        address account;
        for (uint256 i = 0; i < accounts.length;) {
            account = accounts[i];
            if (whitelist.add(account)) {
                emit AddedAccountToList(ListTypes.Whitelist, id, account);
            }

            unchecked {
                ++i;
            }
        }
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
    ) external override
    onlyListOwner(id) 
    notZero(codehashes.length) {
        EnumerableSet.Bytes32Set storage blacklist = codehashBlacklists[id];
        bytes32 codehash;
        for (uint256 i = 0; i < codehashes.length;) {
            codehash = codehashes[i];

            if (codehash == CODEHASH_ZERO) {
                revert CreatorTokenTransferValidator__ZeroCodeHashNotAllowed();
            }

            if (blacklist.add(codehash)) {
                emit AddedCodeHashToList(ListTypes.Blacklist, id, codehash);
            }

            unchecked {
                ++i;
            }
        }
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
    ) external override 
    onlyListOwner(id) 
    notZero(codehashes.length) {
        EnumerableSet.Bytes32Set storage whitelist = codehashWhitelists[id];
        bytes32 codehash;
        for (uint256 i = 0; i < codehashes.length;) {
            codehash = codehashes[i];

            if (codehash == CODEHASH_ZERO) {
                revert CreatorTokenTransferValidator__ZeroCodeHashNotAllowed();
            }

            if (whitelist.add(codehash)) {
                emit AddedCodeHashToList(ListTypes.Whitelist, id, codehash);
            }

            unchecked {
                ++i;
            }
        }
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
    ) external override 
    onlyListOwner(id) 
    notZero(accounts.length) {
        EnumerableSet.AddressSet storage blacklist = blacklists[id];
        address account;
        for (uint256 i = 0; i < accounts.length;) {
            account = accounts[i];
            if (blacklist.remove(account)) {
                emit RemovedAccountFromList(ListTypes.Blacklist, id, account);
            }

            unchecked {
                ++i;
            }
        }
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
    ) external override 
    onlyListOwner(id) 
    notZero(accounts.length) {
        EnumerableSet.AddressSet storage whitelist = whitelists[id];
        address account;
        for (uint256 i = 0; i < accounts.length;) {
            account = accounts[i];
            if (whitelist.remove(account)) {
                emit RemovedAccountFromList(ListTypes.Whitelist, id, account);
            }

            unchecked {
                ++i;
            }
        }
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
    ) external override
    onlyListOwner(id) 
    notZero(codehashes.length) {
        EnumerableSet.Bytes32Set storage blacklist = codehashBlacklists[id];
        bytes32 codehash;
        for (uint256 i = 0; i < codehashes.length;) {
            codehash = codehashes[i];
            if (blacklist.remove(codehash)) {
                emit RemovedCodeHashFromList(ListTypes.Blacklist, id, codehash);
            }

            unchecked {
                ++i;
            }
        }
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
    ) external override
    onlyListOwner(id) 
    notZero(codehashes.length) {
        EnumerableSet.Bytes32Set storage whitelist = codehashWhitelists[id];
        bytes32 codehash;
        for (uint256 i = 0; i < codehashes.length;) {
            codehash = codehashes[i];
            if (whitelist.remove(codehash)) {
                emit RemovedCodeHashFromList(ListTypes.Whitelist, id, codehash);
            }

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Get blacklisted accounts by list id.
     * @param id The id of the list.
     * @return   An array of blacklisted accounts.
     */
    function getBlacklistedAccounts(uint120 id) public view override returns (address[] memory) {
        return blacklists[id].values();
    }

    /**
     * @notice Get whitelisted accounts by list id.
     * @param id The id of the list.
     * @return   An array of whitelisted accounts.
     */
    function getWhitelistedAccounts(uint120 id) public view override returns (address[] memory) {
        return whitelists[id].values();
    }

    /**
     * @notice Get blacklisted codehashes by list id.
     * @param id The id of the list.
     * @return   An array of blacklisted codehashes.
     */
    function getBlacklistedCodeHashes(uint120 id) public view override returns (bytes32[] memory) {
        return codehashBlacklists[id].values();
    }

    /**
     * @notice Get whitelisted codehashes by list id.
     * @param id The id of the list.
     * @return   An array of whitelisted codehashes.
     */
    function getWhitelistedCodeHashes(uint120 id) public view override returns (bytes32[] memory) {
        return codehashWhitelists[id].values();
    }

    /**
     * @notice Check if an account is blacklisted in a specified list.
     * @param id       The id of the list.
     * @param account  The address of the account to check.
     * @return         True if the account is blacklisted in the specified list, false otherwise.
     */
    function isAccountBlacklisted(uint120 id, address account) public view override returns (bool) {
        return blacklists[id].contains(account);
    }

    /**
     * @notice Check if an account is whitelisted in a specified list.
     * @param id       The id of the list.
     * @param account  The address of the account to check.
     * @return         True if the account is whitelisted in the specified list, false otherwise.
     */
    function isAccountWhitelisted(uint120 id, address account) public view override returns (bool) {
        return whitelists[id].contains(account);
    }

    /**
     * @notice Check if a codehash is blacklisted in a specified list.
     * @param id       The id of the list.
     * @param codehash  The codehash to check.
     * @return         True if the codehash is blacklisted in the specified list, false otherwise.
     */
    function isCodeHashBlacklisted(uint120 id, bytes32 codehash) public view override returns (bool) {
        return codehash == CODEHASH_ZERO ? false : codehashBlacklists[id].contains(codehash);
    }

    /**
     * @notice Check if a codehash is whitelisted in a specified list.
     * @param id       The id of the list.
     * @param codehash  The codehash to check.
     * @return         True if the codehash is whitelisted in the specified list, false otherwise.
     */
    function isCodeHashWhitelisted(uint120 id, bytes32 codehash) public view override returns (bool) {
        return codehash == CODEHASH_ZERO ? false : codehashWhitelists[id].contains(codehash);
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
            interfaceId == type(ITransferSecurityRegistryV2).interfaceId ||
            interfaceId == type(ICreatorTokenTransferValidator).interfaceId ||
            interfaceId == type(ICreatorTokenTransferValidatorV2).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    function _isAccountOrCodeHashBlacklisted(uint120 id, address account) internal view returns (bool) {
        EnumerableSet.AddressSet storage ptrBlacklist = blacklists[id];
        EnumerableSet.Bytes32Set storage ptrCodehashBlacklist = codehashBlacklists[id];
        
        return 
        (ptrBlacklist.length() == 0 && ptrCodehashBlacklist.length() == 0) ||
        ptrBlacklist.contains(account) ||
        ptrCodehashBlacklist.contains(account.codehash);
    }

    function _isAccountOrCodeHashWhitelisted(uint120 id, address account) internal view returns (bool) {
        EnumerableSet.AddressSet storage ptrWhitelist = whitelists[id];
        EnumerableSet.Bytes32Set storage ptrCodehashWhitelist = codehashWhitelists[id];
        
        return 
        (ptrWhitelist.length() == 0 && ptrCodehashWhitelist.length() == 0) ||
        ptrWhitelist.contains(account) ||
        ptrCodehashWhitelist.contains(account.codehash);
    }

    function _requireCallerIsNFTOrContractOwnerOrAdmin(address tokenAddress) internal view {
        bool callerHasPermissions = false;
        if(tokenAddress.code.length > 0) {
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

    function _copyAddressSet(
        ListTypes listType,
        uint120 destinationListId,
        EnumerableSet.AddressSet storage ptrFromSet, 
        EnumerableSet.AddressSet storage ptrToSet
    ) private {
        uint256 sourceLength = ptrFromSet.length();
        address account;
        for (uint256 i = 0; i < sourceLength;) {
            account = ptrFromSet.at(i); 
            if (ptrToSet.add(account)) {
                emit AddedAccountToList(listType, destinationListId, account);
            }

            unchecked {
                ++i;
            }
        }
    }

    function _copyBytes32Set(
        ListTypes listType,
        uint120 destinationListId,
        EnumerableSet.Bytes32Set storage ptrFromSet, 
        EnumerableSet.Bytes32Set storage ptrToSet
    ) private {
        uint256 sourceLength = ptrFromSet.length();
        bytes32 codehash;
        for (uint256 i = 0; i < sourceLength;) {
            codehash = ptrFromSet.at(i);
            if (ptrToSet.add(codehash)) {
                emit AddedCodeHashToList(listType, destinationListId, codehash);
            }

            unchecked {
                ++i;
            }
        }
    }

    function _reassignOwnershipOfList(uint120 id, address newOwner) private {
        _requireCallerOwnsList(id);
        listOwners[id] = newOwner;
        emit ReassignedListOwnership(id, newOwner);
    }

    function _requireCallerOwnsList(uint120 id) private view {
        if (_msgSender() != listOwners[id]) {
            revert CreatorTokenTransferValidator__CallerDoesNotOwnList();
        }
    }

    /*************************************************************************/
    /*                        BACKWARDS COMPATIBILITY                        */
    /*************************************************************************/

    /**
     * @notice Maps to `createList` in V2.
     */
    function createOperatorWhitelist(string calldata name) external override returns (uint120) {
        return createList(name);
    }

    /**
     * @notice Maps to `reassignOwnershipOfList` in V2.
     */
    function reassignOwnershipOfOperatorWhitelist(uint120 id, address newOwner) external override {
        reassignOwnershipOfList(id, newOwner);
    }

    /**
     * @notice Maps to `renounceOwnershipOfList` in V2.
     */
    function renounceOwnershipOfOperatorWhitelist(uint120 id) external override {
        renounceOwnershipOfList(id);
    }

    /**
     * @notice Maps to `applyListToCollection` in V2.
     */
    function setOperatorWhitelistOfCollection(address collection, uint120 id) external override {
        applyListToCollection(collection, id);
    }

    /**
     * @notice Adds a single account to the specified whitelist.
     * @dev    Throws when the caller does not own the specified list.
     */
    function addOperatorToWhitelist(uint120 id, address operator) external override onlyListOwner(id) {
        if (whitelists[id].add(operator)) {
            emit AddedAccountToList(ListTypes.Whitelist, id, operator);
        }
    }

    /**
     * @notice Removes a single account from the specified whitelist.
     * @dev    Throws when the caller does not own the specified list.
     */
    function removeOperatorFromWhitelist(uint120 id, address operator) external override onlyListOwner(id) {
        if (whitelists[id].remove(operator)) {
            emit RemovedAccountFromList(ListTypes.Whitelist, id, operator);
        }
    }

    /**
     * @notice Gets the V1 Collection Security Policy information.  
     *         Assigns both operatorWhitelistId and permittedContractReceiversId to the listId.
     */
    function getCollectionSecurityPolicy(address collection) external view override returns (CollectionSecurityPolicy memory) {
        CollectionSecurityPolicyV2 memory collectionSecurityPolicy = collectionSecurityPolicies[collection];

        return CollectionSecurityPolicy({
            transferSecurityLevel: collectionSecurityPolicy.transferSecurityLevel,
            operatorWhitelistId: collectionSecurityPolicy.listId,
            permittedContractReceiversId: collectionSecurityPolicy.listId
        });
    }

    /**
     * @notice Maps to `getWhitelistedAccounts` in V2.
     */
    function getWhitelistedOperators(uint120 id) external view override returns (address[] memory) {
        return getWhitelistedAccounts(id);
    }

    /**
     * @notice Maps to `getWhitelistedAccounts` in V2.
     */
    function getPermittedContractReceivers(uint120 id) external view override returns (address[] memory) {
        return getWhitelistedAccounts(id);
    }

    /**
     * @notice Maps to `isAccountWhitelisted` in V2.
     */
    function isOperatorWhitelisted(uint120 id, address operator) external view override returns (bool) {
        return isAccountWhitelisted(id, operator);
    }

    /**
     * @notice Maps to `isAccountWhitelisted` in V2.
     */
    function isContractReceiverPermitted(uint120 id, address receiver) external view override returns (bool) {
        return isAccountWhitelisted(id, receiver);
    }

    /**
     * @notice NO-OP Because V2 Allows Whitelisted Accounts To Be Contract Receivers Automatically.
     * @return 0
     */
    function createPermittedContractReceiverAllowlist(string calldata /*name*/) external pure override returns (uint120) {
        return 0;
    }

    /**
     * @notice NO-OP Because V2 Allows Whitelisted Accounts To Be Contract Receivers Automatically.
     */
    function reassignOwnershipOfPermittedContractReceiverAllowlist(
        uint120 /*id*/, 
        address /*newOwner*/
    ) external pure override {}

    /**
     * @notice NO-OP Because V2 Allows Whitelisted Accounts To Be Contract Receivers Automatically.
     */
    function renounceOwnershipOfPermittedContractReceiverAllowlist(uint120 /*id*/) external pure override {}

    /**
     * @notice NO-OP Because V2 Allows Whitelisted Accounts To Be Contract Receivers Automatically.
     */
    function setPermittedContractReceiverAllowlistOfCollection(
        address /*collection*/, 
        uint120 /*id*/
    ) external pure override {}

    /**
     * @notice NO-OP Because V2 Allows Whitelisted Accounts To Be Contract Receivers Automatically.
     */
    function addPermittedContractReceiverToAllowlist(uint120 /*id*/, address /*receiver*/) external pure override {}

    /**
     * @notice NO-OP Because V2 Allows Whitelisted Accounts To Be Contract Receivers Automatically.
     */
    function removePermittedContractReceiverFromAllowlist(
        uint120 /*id*/, 
        address /*receiver*/
    ) external pure override {}
}