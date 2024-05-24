// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/console.sol";
import "./mocks/ClonerMock.sol";
import "./mocks/ContractMock.sol";
import "./mocks/ERC721CMock.sol";
import "./interfaces/ITestCreatorToken.sol";
import "src/utils/TransferPolicy.sol";
import {CreatorTokenTransferValidator, IPermitC} from "src/utils/CreatorTokenTransferValidator.sol";
import {CreatorTokenTransferValidatorConfiguration} from "src/utils/CreatorTokenTransferValidatorConfiguration.sol";
import "src/Constants.sol";
import "./utils/Events.sol";
import "./utils/Helpers.sol";
import "./EOARegistry.t.sol";

contract TransferValidatorTest is Events, EOARegistryTest {
    CreatorTokenTransferValidator public validator;
    CreatorTokenTransferValidatorConfiguration public validatorConfiguration;

    function setUp() public virtual override {
        super.setUp();

        validatorConfiguration = new CreatorTokenTransferValidatorConfiguration(address(this));
        validatorConfiguration.setNativeValueToCheckPauseState(0);

        vm.expectEmit(true, true, true, true);
        emit CreatorTokenTransferValidator.CreatedList(0, "DEFAULT LIST");
        vm.expectEmit(true, true, true, true);
        emit CreatorTokenTransferValidator.ReassignedListOwnership(0, address(this));
        validator = new CreatorTokenTransferValidator(address(this), address(eoaRegistry), "", "", address(validatorConfiguration));
    }

    function testSupportedInterfaces() public {
        assertEq(validator.supportsInterface(bytes4(0x00000000)), true);
        assertEq(validator.supportsInterface(type(ITransferValidator).interfaceId), true);
        assertEq(validator.supportsInterface(type(IPermitC).interfaceId), true);
        assertEq(validator.supportsInterface(type(IEOARegistry).interfaceId), true);
        assertEq(validator.supportsInterface(type(IERC165).interfaceId), true);
    }

    function testTransferSecurityLevelRecommended() public {
        (uint256 callerConstraints, uint256 receiverConstraints) = validator.transferSecurityPolicies(TRANSFER_SECURITY_LEVEL_RECOMMENDED);
        assertEq(TRANSFER_SECURITY_LEVEL_RECOMMENDED, 0);
        assertTrue(callerConstraints == CALLER_CONSTRAINTS_OPERATOR_WHITELIST_ENABLE_OTC);
        assertTrue(receiverConstraints == RECEIVER_CONSTRAINTS_NONE);
    }

    function testTransferSecurityLevelOne() public {
        (uint256 callerConstraints, uint256 receiverConstraints) = validator.transferSecurityPolicies(TRANSFER_SECURITY_LEVEL_ONE);
        assertEq(TRANSFER_SECURITY_LEVEL_ONE, 1);
        assertTrue(callerConstraints == CALLER_CONSTRAINTS_NONE);
        assertTrue(receiverConstraints == RECEIVER_CONSTRAINTS_NONE);
    }

    function testTransferSecurityLevelTwo() public {
        (uint256 callerConstraints, uint256 receiverConstraints) = validator.transferSecurityPolicies(TRANSFER_SECURITY_LEVEL_TWO);
        assertEq(TRANSFER_SECURITY_LEVEL_TWO, 2);
        assertTrue(callerConstraints == CALLER_CONSTRAINTS_OPERATOR_BLACKLIST_ENABLE_OTC);
        assertTrue(receiverConstraints == RECEIVER_CONSTRAINTS_NONE);
    }

    function testTransferSecurityLevelThree() public {
        (uint256 callerConstraints, uint256 receiverConstraints) = validator.transferSecurityPolicies(TRANSFER_SECURITY_LEVEL_THREE);
        assertEq(TRANSFER_SECURITY_LEVEL_THREE, 3);
        assertTrue(callerConstraints == CALLER_CONSTRAINTS_OPERATOR_WHITELIST_ENABLE_OTC);
        assertTrue(receiverConstraints == RECEIVER_CONSTRAINTS_NONE);
    }

    function testTransferSecurityLevelFour() public {
        (uint256 callerConstraints, uint256 receiverConstraints) = validator.transferSecurityPolicies(TRANSFER_SECURITY_LEVEL_FOUR);
        assertEq(TRANSFER_SECURITY_LEVEL_FOUR, 4);
        assertTrue(callerConstraints == CALLER_CONSTRAINTS_OPERATOR_WHITELIST_DISABLE_OTC);
        assertTrue(receiverConstraints == RECEIVER_CONSTRAINTS_NONE);
    }

    function testTransferSecurityLevelFive() public {
        (uint256 callerConstraints, uint256 receiverConstraints) = validator.transferSecurityPolicies(TRANSFER_SECURITY_LEVEL_FIVE);
        assertEq(TRANSFER_SECURITY_LEVEL_FIVE, 5);
        assertTrue(callerConstraints == CALLER_CONSTRAINTS_OPERATOR_WHITELIST_ENABLE_OTC);
        assertTrue(receiverConstraints == RECEIVER_CONSTRAINTS_NO_CODE);
    }

    function testTransferSecurityLevelSix() public {
        (uint256 callerConstraints, uint256 receiverConstraints) = validator.transferSecurityPolicies(TRANSFER_SECURITY_LEVEL_SIX);
        assertEq(TRANSFER_SECURITY_LEVEL_SIX, 6);
        assertTrue(callerConstraints == CALLER_CONSTRAINTS_OPERATOR_WHITELIST_ENABLE_OTC);
        assertTrue(receiverConstraints == RECEIVER_CONSTRAINTS_EOA);
    }

    function testTransferSecurityLevelSeven() public {
        (uint256 callerConstraints, uint256 receiverConstraints) = validator.transferSecurityPolicies(TRANSFER_SECURITY_LEVEL_SEVEN);
        assertEq(TRANSFER_SECURITY_LEVEL_SEVEN, 7);
        assertTrue(callerConstraints == CALLER_CONSTRAINTS_OPERATOR_WHITELIST_DISABLE_OTC);
        assertTrue(receiverConstraints == RECEIVER_CONSTRAINTS_NO_CODE);
    }

    function testTransferSecurityLevelEight() public {
        (uint256 callerConstraints, uint256 receiverConstraints) = validator.transferSecurityPolicies(TRANSFER_SECURITY_LEVEL_EIGHT);
        assertEq(TRANSFER_SECURITY_LEVEL_EIGHT, 8);
        assertTrue(callerConstraints == CALLER_CONSTRAINTS_OPERATOR_WHITELIST_DISABLE_OTC);
        assertTrue(receiverConstraints == RECEIVER_CONSTRAINTS_EOA);
    }

    function testTransferSecurityLevelNine() public {
        (uint256 callerConstraints, uint256 receiverConstraints) = validator.transferSecurityPolicies(TRANSFER_SECURITY_LEVEL_NINE);
        assertEq(TRANSFER_SECURITY_LEVEL_NINE, 9);
        assertTrue(callerConstraints == CALLER_CONSTRAINTS_SBT);
        assertTrue(receiverConstraints == RECEIVER_CONSTRAINTS_SBT);
    }

    function testCreateList(address listOwner, bytes32 nameBytes) public {
        _sanitizeAddress(listOwner);
        string memory name = string(abi.encodePacked(nameBytes));

        uint120 firstListId = 1;
        for (uint120 i = 0; i < 5; ++i) {
            uint120 expectedId = firstListId + i;

            vm.expectEmit(true, true, true, false);
            emit CreatedList(expectedId, name);

            vm.expectEmit(true, true, true, false);
            emit ReassignedListOwnership(expectedId, listOwner);

            vm.prank(listOwner);
            uint120 actualId = validator.createList(name);
            assertEq(actualId, expectedId);
            assertEq(validator.listOwners(actualId), listOwner);
        }
    }

    function testCreateListCopy(
        address listOwner, 
        address listCopyOwner, 
        bytes32 nameBytes, 
        bytes32 nameBytesCopy,
        address whitelistedAccount,
        address blacklistedAccount,
        address authorizerAccount
    ) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(listCopyOwner);
        _sanitizeAddress(whitelistedAccount);
        _sanitizeAddress(blacklistedAccount);
        _sanitizeAddress(authorizerAccount);
        string memory name = string(abi.encodePacked(nameBytes));
        string memory nameCopy = string(abi.encodePacked(nameBytesCopy));

        bytes32[] memory whitelistedCodeHashes = new bytes32[](2);
        whitelistedCodeHashes[0] = keccak256(abi.encode(whitelistedAccount));
        whitelistedCodeHashes[1] = keccak256(abi.encode(whitelistedCodeHashes[0]));

        bytes32[] memory blacklistedCodeHashes = new bytes32[](2);
        blacklistedCodeHashes[0] = keccak256(abi.encode(blacklistedAccount));
        blacklistedCodeHashes[1] = keccak256(abi.encode(blacklistedCodeHashes[0]));

        vm.startPrank(listOwner);
        uint120 sourceListId = validator.createList(name);
        validator.addAccountsToWhitelist(sourceListId, _asSingletonArray(whitelistedAccount));
        validator.addAccountsToWhitelist(sourceListId, _asSingletonArray(address(uint160(uint256(keccak256(abi.encode(whitelistedAccount)))))));
        validator.addAccountsToBlacklist(sourceListId, _asSingletonArray(blacklistedAccount));
        validator.addAccountsToBlacklist(sourceListId, _asSingletonArray(address(uint160(uint256(keccak256(abi.encode(blacklistedAccount)))))));
        validator.addAccountsToAuthorizers(sourceListId, _asSingletonArray(authorizerAccount));
        validator.addAccountsToAuthorizers(sourceListId, _asSingletonArray(address(uint160(uint256(keccak256(abi.encode(authorizerAccount)))))));
        validator.addCodeHashesToWhitelist(sourceListId, whitelistedCodeHashes);
        validator.addCodeHashesToBlacklist(sourceListId, blacklistedCodeHashes);
        vm.stopPrank();

        uint120 expectedCopyListId = validator.lastListId() + 1;

        vm.expectEmit(true, true, true, false);
        emit CreatedList(expectedCopyListId, name);

        vm.expectEmit(true, true, true, false);
        emit ReassignedListOwnership(expectedCopyListId, listCopyOwner);

        vm.prank(listCopyOwner);
        uint120 copyId = validator.createListCopy(nameCopy, sourceListId);

        assertEq(copyId, expectedCopyListId);
        assertEq(validator.listOwners(copyId), listCopyOwner);

        address[] memory sourceWhitelistedAccounts = validator.getWhitelistedAccounts(sourceListId);
        address[] memory sourceBlacklistedAccounts = validator.getBlacklistedAccounts(sourceListId);
        address[] memory sourceAuthorizerAccounts = validator.getAuthorizerAccounts(sourceListId);
        bytes32[] memory sourceWhitelistedCodeHashes = validator.getWhitelistedCodeHashes(sourceListId);
        bytes32[] memory sourceBlacklistedCodeHashes = validator.getBlacklistedCodeHashes(sourceListId);

        address[] memory copyWhitelistedAccounts = validator.getWhitelistedAccounts(copyId);
        address[] memory copyBlacklistedAccounts = validator.getBlacklistedAccounts(copyId);
        address[] memory copyAuthorizerAccounts = validator.getAuthorizerAccounts(copyId);
        bytes32[] memory copyWhitelistedCodeHashes = validator.getWhitelistedCodeHashes(copyId);
        bytes32[] memory copyBlacklistedCodeHashes = validator.getBlacklistedCodeHashes(copyId);

        assertEq(sourceWhitelistedAccounts.length, copyWhitelistedAccounts.length);
        assertEq(sourceBlacklistedAccounts.length, copyBlacklistedAccounts.length);
        assertEq(sourceAuthorizerAccounts.length, copyAuthorizerAccounts.length);
        assertEq(sourceWhitelistedCodeHashes.length, copyWhitelistedCodeHashes.length);
        assertEq(sourceBlacklistedCodeHashes.length, copyBlacklistedCodeHashes.length);

        for (uint256 i = 0; i < sourceWhitelistedAccounts.length; i++) {
            assertEq(sourceWhitelistedAccounts[i], copyWhitelistedAccounts[i]);
        }

        for (uint256 i = 0; i < sourceBlacklistedAccounts.length; i++) {
            assertEq(sourceBlacklistedAccounts[i], copyBlacklistedAccounts[i]);
        }

        for (uint256 i = 0; i < sourceAuthorizerAccounts.length; i++) {
            assertEq(sourceAuthorizerAccounts[i], copyAuthorizerAccounts[i]);
        }

        for (uint256 i = 0; i < sourceWhitelistedCodeHashes.length; i++) {
            assertEq(sourceWhitelistedCodeHashes[i], copyWhitelistedCodeHashes[i]);
        }

        for (uint256 i = 0; i < sourceBlacklistedCodeHashes.length; i++) {
            assertEq(sourceBlacklistedCodeHashes[i], copyBlacklistedCodeHashes[i]);
        }
    }

    function testRevertsWhenCopyingNonExistentList(uint120 sourceListId) public {
        uint120 lastKnownListId = validator.lastListId();
        sourceListId = uint120(bound(sourceListId, lastKnownListId + 1, type(uint120).max));

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__ListDoesNotExist.selector);
        validator.createListCopy("test", sourceListId);
    }

    function testReassignOwnershipOfList(address originalListOwner, address newListOwner) public {
        _sanitizeAddress(originalListOwner);
        _sanitizeAddress(newListOwner);
        vm.assume(originalListOwner != newListOwner);

        vm.prank(originalListOwner);
        uint120 listId = validator.createList("test");

        vm.expectEmit(true, true, true, false);
        emit ReassignedListOwnership(listId, newListOwner);

        vm.prank(originalListOwner);
        validator.reassignOwnershipOfList(listId, newListOwner);
        assertEq(validator.listOwners(listId), newListOwner);
    }

    function testRevertsWhenReassigningOwnershipOfListToZero(address originalListOwner) public {
        _sanitizeAddress(originalListOwner);

        vm.prank(originalListOwner);
        uint120 listId = validator.createList("test");

        vm.expectRevert(
            CreatorTokenTransferValidator
                .CreatorTokenTransferValidator__ListOwnershipCannotBeTransferredToZeroAddress
                .selector
        );
        validator.reassignOwnershipOfList(listId, address(0));
    }

    function testRevertsWhenNonOwnerReassignsOwnershipOfList(
        address originalListOwner,
        address unauthorizedUser
    ) public {
        _sanitizeAddress(originalListOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(originalListOwner != unauthorizedUser);

        vm.prank(originalListOwner);
        uint120 listId = validator.createList("test");

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.reassignOwnershipOfList(listId, unauthorizedUser);
    }

    function testRenounceOwnershipOfList(address originalListOwner) public {
        _sanitizeAddress(originalListOwner);

        vm.prank(originalListOwner);
        uint120 listId = validator.createList("test");

        vm.expectEmit(true, true, true, false);
        emit ReassignedListOwnership(listId, address(0));

        vm.prank(originalListOwner);
        validator.renounceOwnershipOfList(listId);
        assertEq(validator.listOwners(listId), address(0));
    }

    function testRevertsWhenNonOwnerRenouncesOwnershipOfList(
        address originalListOwner,
        address unauthorizedUser
    ) public {
        _sanitizeAddress(originalListOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(originalListOwner != unauthorizedUser);

        vm.prank(originalListOwner);
        uint120 listId = validator.createList("test");

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.renounceOwnershipOfList(listId);
    }

    function testSetTransferSecurityLevelOfCollection(
        address collection,
        uint8 level,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        _sanitizeAddress(collection);

        level = uint8(bound(level, TRANSFER_SECURITY_LEVEL_RECOMMENDED, TRANSFER_SECURITY_LEVEL_NINE));

        vm.expectEmit(true, true, true, true);
        emit SetTransferSecurityLevel(collection, level);

        vm.expectEmit(true, true, true, true);
        emit SetAuthorizationModeEnabled(collection, disableAuthorizationMode, authorizersCannotSetWildcardOperators);

        vm.expectEmit(true, true, true, true);
        emit SetAccountFreezingModeEnabled(collection, enableAccountFreezingMode);

        vm.prank(collection);
        validator.setTransferSecurityLevelOfCollection(
            collection, 
            level, 
            disableAuthorizationMode, 
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode);

        CollectionSecurityPolicyV3 memory policy = validator.getCollectionSecurityPolicy(collection);

        assertEq(policy.transferSecurityLevel, level);
        assertEq(policy.disableAuthorizationMode, disableAuthorizationMode);
        assertEq(policy.authorizersCannotSetWildcardOperators, authorizersCannotSetWildcardOperators);
        assertEq(policy.enableAccountFreezingMode, enableAccountFreezingMode);
    }

    function testRevertsWhenSecurityLevelOutOfRangeForSetTransferSecurityLevelOfCollection(
        address collection,
        uint8 level,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        _sanitizeAddress(collection);

        level = uint8(bound(level, TRANSFER_SECURITY_LEVEL_NINE + 1, type(uint8).max));

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__InvalidTransferSecurityLevel.selector);
        vm.prank(collection);
        validator.setTransferSecurityLevelOfCollection(collection, level, disableAuthorizationMode, authorizersCannotSetWildcardOperators, enableAccountFreezingMode);
    }

    function testRevertsWhenUnauthorizedUserCallsSetTransferSecurityLevelOfCollection(
        address collection,
        address unauthorizedUser,
        uint8 level,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        _sanitizeAddress(collection);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(collection != unauthorizedUser);

        level = uint8(bound(level, TRANSFER_SECURITY_LEVEL_RECOMMENDED, TRANSFER_SECURITY_LEVEL_NINE));

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustHaveElevatedPermissionsForSpecifiedNFT.selector);
        vm.prank(unauthorizedUser);
        validator.setTransferSecurityLevelOfCollection(collection, level, disableAuthorizationMode, authorizersCannotSetWildcardOperators, enableAccountFreezingMode);
    }

    function testApplyListToCollection(address collection) public {
        _sanitizeAddress(collection);

        uint120 listId = validator.createList("test");

        vm.expectEmit(true, true, true, true);
        emit AppliedListToCollection(collection, listId);

        vm.prank(collection);
        validator.applyListToCollection(collection, listId);

        CollectionSecurityPolicyV3 memory policy = validator.getCollectionSecurityPolicy(collection);
        assertEq(policy.listId, listId);
    }

    function testRevertsWhenApplyingNonExistentListIdToCollection(address collection, uint120 listId) public {
        _sanitizeAddress(collection);
        listId = uint120(bound(listId, validator.lastListId() + 1, type(uint120).max));

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__ListDoesNotExist.selector);
        vm.prank(collection);
        validator.applyListToCollection(collection, listId);
    }

    function testRevertsWhenUnauthorizedUserAppliesListToCollection(
        address collection,
        address unauthorizedUser,
        uint120 listId
    ) public {
        _sanitizeAddress(collection);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(collection != unauthorizedUser);

        listId = uint120(bound(listId, 0, validator.lastListId()));

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustHaveElevatedPermissionsForSpecifiedNFT.selector);
        vm.prank(unauthorizedUser);
        validator.applyListToCollection(collection, listId);
    }

    function testFreezeAccountsForCollection(address collection, uint256 numAccountsToFreeze, address[10] memory accounts) public {
        _sanitizeAddress(collection);
        numAccountsToFreeze = bound(numAccountsToFreeze, 1, 10);

        uint256 expectedNumAccountsFrozen = 0;
        address[] memory accountsToFreeze = new address[](numAccountsToFreeze);
        for (uint256 i = 0; i < numAccountsToFreeze; i++) {
            bool firstTimeAccount = true;
            for (uint256 j = 0; j < i; j++) {
                if (accountsToFreeze[j] == accounts[i]) {
                    firstTimeAccount = false;
                    break;
                }
            }

            accountsToFreeze[i] = accounts[i];

            if (firstTimeAccount) {
                expectedNumAccountsFrozen++;
                vm.expectEmit(true, true, true, true);
                emit AccountFrozenForCollection(collection, accounts[i]);
            }
        }

        vm.prank(collection);
        validator.freezeAccountsForCollection(collection, accountsToFreeze);

        for (uint256 i = 0; i < numAccountsToFreeze; i++) {
            assertTrue(validator.isAccountFrozenForCollection(collection, accountsToFreeze[i]));
        }

        address[] memory frozenAccounts = validator.getFrozenAccountsByCollection(collection);
        assertEq(frozenAccounts.length, expectedNumAccountsFrozen);
    }

    function testRevertsWhenUnauthorizedUserCallsFreezeAccountsForCollection(
        address collection,
        address unauthorizedUser,
        uint256 numAccountsToFreeze,
        address[10] memory accounts
    ) public {
        _sanitizeAddress(collection);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(collection != unauthorizedUser);

        numAccountsToFreeze = bound(numAccountsToFreeze, 1, 10);

        address[] memory accountsToFreeze = new address[](numAccountsToFreeze);
        for (uint256 i = 0; i < numAccountsToFreeze; i++) {
            accountsToFreeze[i] = accounts[i];
        }

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustHaveElevatedPermissionsForSpecifiedNFT.selector);
        vm.prank(unauthorizedUser);
        validator.freezeAccountsForCollection(collection, accountsToFreeze);
    }

    function testUnfreezeAccountsForCollection(address collection, uint256 numAccountsToUnfreeze, address[10] memory accounts) public {
        _sanitizeAddress(collection);
        numAccountsToUnfreeze = bound(numAccountsToUnfreeze, 1, 10);

        address[] memory preFrozenAccounts = new address[](10);
        for (uint256 i = 0; i < 10; i++) {
            preFrozenAccounts[i] = accounts[i];
        }

        vm.prank(collection);
        validator.freezeAccountsForCollection(collection, preFrozenAccounts);

        uint256 numPreFrozenAccounts = validator.getFrozenAccountsByCollection(collection).length;

        uint256 expectedNumAccountsUnfrozen = 0;
        address[] memory accountsToUnfreeze = new address[](numAccountsToUnfreeze);
        for (uint256 i = 0; i < numAccountsToUnfreeze; i++) {
            bool firstTimeAccount = true;
            for (uint256 j = 0; j < i; j++) {
                if (accountsToUnfreeze[j] == accounts[i]) {
                    firstTimeAccount = false;
                    break;
                }
            }

            accountsToUnfreeze[i] = accounts[i];

            if (firstTimeAccount) {
                expectedNumAccountsUnfrozen++;
                vm.expectEmit(true, true, true, true);
                emit AccountUnfrozenForCollection(collection, accounts[i]);
            }
        }

        vm.prank(collection);
        validator.unfreezeAccountsForCollection(collection, accountsToUnfreeze);

        for (uint256 i = 0; i < numAccountsToUnfreeze; i++) {
            assertFalse(validator.isAccountFrozenForCollection(collection, accountsToUnfreeze[i]));
        }

        address[] memory frozenAccounts = validator.getFrozenAccountsByCollection(collection);
        assertEq(frozenAccounts.length, numPreFrozenAccounts - expectedNumAccountsUnfrozen);
    }

    function testRevertsWhenUnauthorizedUserCallsUnfreezeAccountsForCollection(
        address collection,
        address unauthorizedUser,
        uint256 numAccountsToUnfreeze,
        address[10] memory accounts
    ) public {
        _sanitizeAddress(collection);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(collection != unauthorizedUser);

        numAccountsToUnfreeze = bound(numAccountsToUnfreeze, 1, 10);

        address[] memory accountsToUnfreeze = new address[](numAccountsToUnfreeze);
        for (uint256 i = 0; i < numAccountsToUnfreeze; i++) {
            accountsToUnfreeze[i] = accounts[i];
        }

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustHaveElevatedPermissionsForSpecifiedNFT.selector);
        vm.prank(unauthorizedUser);
        validator.unfreezeAccountsForCollection(collection, accountsToUnfreeze);
    }

    function testAddAccountToBlacklist(address listOwner, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account);

        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        vm.expectEmit(true, true, true, true);
        emit AddedAccountToList(LIST_TYPE_BLACKLIST, listId, account);

        vm.prank(listOwner);
        validator.addAccountsToBlacklist(listId, _asSingletonArray(account));
        assertTrue(validator.isAccountBlacklisted(listId, account));
    }

    function testRevertsWhenUnauthorizedUserAddsAccountToBlacklist(
        address listOwner,
        address unauthorizedUser,
        address account
    ) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        _sanitizeAddress(account);
        vm.assume(listOwner != unauthorizedUser);

        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addAccountsToBlacklist(listId, _asSingletonArray(account));
    }

    function testAddAccountsToBlacklist(address listOwner, uint256 numAccountsToBlacklist, address[10] memory accounts) public {
        _sanitizeAddress(listOwner);
        numAccountsToBlacklist = bound(numAccountsToBlacklist, 0, 10);

        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        uint256 expectedNumAccountsBlacklisted = 0;
        address[] memory accountsToBlacklist = new address[](numAccountsToBlacklist);
        for (uint256 i = 0; i < numAccountsToBlacklist; i++) {
            bool firstTimeAccount = true;
            for (uint256 j = 0; j < i; j++) {
                if (accountsToBlacklist[j] == accounts[i]) {
                    firstTimeAccount = false;
                    break;
                }
            }

            accountsToBlacklist[i] = accounts[i];

            if (firstTimeAccount) {
                expectedNumAccountsBlacklisted++;
                vm.expectEmit(true, true, true, true);
                emit AddedAccountToList(LIST_TYPE_BLACKLIST, listId, accounts[i]);
            }
        }

        vm.prank(listOwner);
        validator.addAccountsToBlacklist(listId, accountsToBlacklist);

        for (uint256 i = 0; i < numAccountsToBlacklist; i++) {
            assertTrue(validator.isAccountBlacklisted(listId, accountsToBlacklist[i]));
        }

        address[] memory blacklistedAccounts = validator.getBlacklistedAccounts(listId);
        assertEq(blacklistedAccounts.length, expectedNumAccountsBlacklisted);
    }

    function testRevertsWhenUnauthorizedUserAddsAccountsToBlacklist(
        address listOwner,
        address unauthorizedUser,
        uint256 numAccountsToBlacklist,
        address[10] memory accounts
    ) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);

        numAccountsToBlacklist = bound(numAccountsToBlacklist, 1, 10);

        address[] memory accountsToBlacklist = new address[](numAccountsToBlacklist);
        for (uint256 i = 0; i < numAccountsToBlacklist; i++) {
            accountsToBlacklist[i] = accounts[i];
        }

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addAccountsToBlacklist(0, accountsToBlacklist);
    }

    function testRemoveAccountFromBlacklist(address listOwner, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account);

        vm.startPrank(listOwner);
        uint120 listId = validator.createList("test");
        validator.addAccountsToBlacklist(listId, _asSingletonArray(account));

        vm.expectEmit(true, true, true, true);
        emit RemovedAccountFromList(LIST_TYPE_BLACKLIST, listId, account);

        validator.removeAccountsFromBlacklist(listId, _asSingletonArray(account));
        assertFalse(validator.isAccountBlacklisted(listId, account));
        vm.stopPrank();
    }

    function testRevertsWhenUnauthorizedUserRemovesAccountFromBlacklist(
        address listOwner,
        address unauthorizedUser,
        address account
    ) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        _sanitizeAddress(account);
        vm.assume(listOwner != unauthorizedUser);

        vm.startPrank(listOwner);
        uint120 listId = validator.createList("test");
        validator.addAccountsToBlacklist(listId, _asSingletonArray(account));
        vm.stopPrank();

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.removeAccountsFromBlacklist(listId, _asSingletonArray(account));
    }

    function testRemoveAccountsFromBlacklist(address listOwner, uint256 numAccountsToRemove, address[10] memory accounts) public {
        _sanitizeAddress(listOwner);
        numAccountsToRemove = bound(numAccountsToRemove, 1, 10);

        vm.startPrank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accountsToBlacklist = new address[](10);
        for (uint256 i = 0; i < 10; i++) {
            accountsToBlacklist[i] = accounts[i];
        }

        validator.addAccountsToBlacklist(listId, accountsToBlacklist);
        vm.stopPrank();

        uint256 numPreBlacklistedAccounts = validator.getBlacklistedAccounts(listId).length;

        uint256 expectedNumAccountsRemoved = 0;
        address[] memory accountsToRemove = new address[](numAccountsToRemove);
        for (uint256 i = 0; i < numAccountsToRemove; i++) {
            bool firstTimeAccount = true;
            for (uint256 j = 0; j < i; j++) {
                if (accountsToRemove[j] == accounts[i]) {
                    firstTimeAccount = false;
                    break;
                }
            }

            accountsToRemove[i] = accounts[i];

            if (firstTimeAccount) {
                expectedNumAccountsRemoved++;
                vm.expectEmit(true, true, true, true);
                emit RemovedAccountFromList(LIST_TYPE_BLACKLIST, listId, accounts[i]);
            }
        }

        vm.prank(listOwner);
        validator.removeAccountsFromBlacklist(listId, accountsToRemove);

        for (uint256 i = 0; i < numAccountsToRemove; i++) {
            assertFalse(validator.isAccountBlacklisted(listId, accountsToRemove[i]));
        }

        address[] memory blacklistedAccounts = validator.getBlacklistedAccounts(listId);
        assertEq(blacklistedAccounts.length, numPreBlacklistedAccounts - expectedNumAccountsRemoved);
    }

    function testRevertsWhenUnauthorizedUserRemovesAccountsFromBlacklist(
        address listOwner,
        address unauthorizedUser,
        uint256 numAccountsToRemove,
        address[10] memory accounts
    ) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);

        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        numAccountsToRemove = bound(numAccountsToRemove, 1, 10);

        address[] memory accountsToRemove = new address[](numAccountsToRemove);
        for (uint256 i = 0; i < numAccountsToRemove; i++) {
            accountsToRemove[i] = accounts[i];
        }

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.removeAccountsFromBlacklist(listId, accountsToRemove);
    }

    function testAddAccountToWhitelist(address listOwner, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account);

        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        vm.expectEmit(true, true, true, true);
        emit AddedAccountToList(LIST_TYPE_WHITELIST, listId, account);

        vm.prank(listOwner);
        validator.addAccountsToWhitelist(listId, _asSingletonArray(account));
        assertTrue(validator.isAccountWhitelisted(listId, account));
    }

    function testRevertsWhenUnauthorizedUserAddsAccountToWhitelist(
        address listOwner,
        address unauthorizedUser,
        address account
    ) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        _sanitizeAddress(account);
        vm.assume(listOwner != unauthorizedUser);

        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addAccountsToWhitelist(listId, _asSingletonArray(account));
    }

    function testAddAccountsToWhitelist(address listOwner, uint256 numAccountsToWhitelist, address[10] memory accounts) public {
        _sanitizeAddress(listOwner);
        numAccountsToWhitelist = bound(numAccountsToWhitelist, 1, 10);

        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        uint256 expectedNumAccountsWhitelisted = 0;
        address[] memory accountsToWhitelist = new address[](numAccountsToWhitelist);
        for (uint256 i = 0; i < numAccountsToWhitelist; i++) {
            bool firstTimeAccount = true;
            for (uint256 j = 0; j < i; j++) {
                if (accountsToWhitelist[j] == accounts[i]) {
                    firstTimeAccount = false;
                    break;
                }
            }

            accountsToWhitelist[i] = accounts[i];

            if (firstTimeAccount) {
                expectedNumAccountsWhitelisted++;
                vm.expectEmit(true, true, true, true);
                emit AddedAccountToList(LIST_TYPE_WHITELIST, listId, accounts[i]);
            }
        }

        vm.prank(listOwner);
        validator.addAccountsToWhitelist(listId, accountsToWhitelist);

        for (uint256 i = 0; i < numAccountsToWhitelist; i++) {
            assertTrue(validator.isAccountWhitelisted(listId, accountsToWhitelist[i]));
        }

        address[] memory whitelistedAccounts = validator.getWhitelistedAccounts(listId);
        assertEq(whitelistedAccounts.length, expectedNumAccountsWhitelisted);
    }

    function testRevertsWhenUnauthorizedUserAddsAccountsToWhitelist(
        address listOwner,
        address unauthorizedUser,
        uint256 numAccountsToWhitelist,
        address[10] memory accounts
    ) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);

        numAccountsToWhitelist = bound(numAccountsToWhitelist, 1, 10);

        address[] memory accountsToWhitelist = new address[](numAccountsToWhitelist);
        for (uint256 i = 0; i < numAccountsToWhitelist; i++) {
            accountsToWhitelist[i] = accounts[i];
        }

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addAccountsToWhitelist(0, accountsToWhitelist);
    }

    function testRemoveAccountFromWhitelist(address listOwner, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account);

        vm.startPrank(listOwner);
        uint120 listId = validator.createList("test");
        validator.addAccountsToWhitelist(listId, _asSingletonArray(account));

        vm.expectEmit(true, true, true, true);
        emit RemovedAccountFromList(LIST_TYPE_WHITELIST, listId, account);

        validator.removeAccountsFromWhitelist(listId, _asSingletonArray(account));
        assertFalse(validator.isAccountWhitelisted(listId, account));
        vm.stopPrank();
    }

    function testRevertsWhenUnauthorizedUserRemovesAccountFromWhitelist(
        address listOwner,
        address unauthorizedUser,
        address account
    ) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        _sanitizeAddress(account);
        vm.assume(listOwner != unauthorizedUser);

        vm.startPrank(listOwner);
        uint120 listId = validator.createList("test");
        validator.addAccountsToWhitelist(listId, _asSingletonArray(account));
        vm.stopPrank();

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.removeAccountsFromWhitelist(listId, _asSingletonArray(account));
    }

    function testRemoveAccountsFromWhitelist(address listOwner, uint256 numAccountsToRemove, address[10] memory accounts) public {
        _sanitizeAddress(listOwner);
        numAccountsToRemove = bound(numAccountsToRemove, 1, 10);

        vm.startPrank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accountsToWhitelist = new address[](10);
        for (uint256 i = 0; i < 10; i++) {
            accountsToWhitelist[i] = accounts[i];
        }

        validator.addAccountsToWhitelist(listId, accountsToWhitelist);
        vm.stopPrank();

        uint256 numPreWhitelistedAccounts = validator.getWhitelistedAccounts(listId).length;

        uint256 expectedNumAccountsRemoved = 0;
        address[] memory accountsToRemove = new address[](numAccountsToRemove);
        for (uint256 i = 0; i < numAccountsToRemove; i++) {
            bool firstTimeAccount = true;
            for (uint256 j = 0; j < i; j++) {
                if (accountsToRemove[j] == accounts[i]) {
                    firstTimeAccount = false;
                    break;
                }
            }

            accountsToRemove[i] = accounts[i];

            if (firstTimeAccount) {
                expectedNumAccountsRemoved++;
                vm.expectEmit(true, true, true, true);
                emit RemovedAccountFromList(LIST_TYPE_WHITELIST, listId, accounts[i]);
            }
        }

        vm.prank(listOwner);
        validator.removeAccountsFromWhitelist(listId, accountsToRemove);

        for (uint256 i = 0; i < numAccountsToRemove; i++) {
            assertFalse(validator.isAccountWhitelisted(listId, accountsToRemove[i]));
        }

        address[] memory whitelistedAccounts = validator.getWhitelistedAccounts(listId);
        assertEq(whitelistedAccounts.length, numPreWhitelistedAccounts - expectedNumAccountsRemoved);
    }

    function testRevertsWhenUnauthorizedUserRemovesAccountsFromWhitelist(
        address listOwner,
        address unauthorizedUser,
        uint256 numAccountsToRemove,
        address[10] memory accounts
    ) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);

        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        numAccountsToRemove = bound(numAccountsToRemove, 1, 10);

        address[] memory accountsToRemove = new address[](numAccountsToRemove);
        for (uint256 i = 0; i < numAccountsToRemove; i++) {
            accountsToRemove[i] = accounts[i];
        }

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.removeAccountsFromWhitelist(listId, accountsToRemove);
    }

    function testAddAccountToAuthorizerList(address listOwner, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account);

        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        vm.expectEmit(true, true, true, true);
        emit AddedAccountToList(LIST_TYPE_AUTHORIZERS, listId, account);

        vm.prank(listOwner);
        validator.addAccountsToAuthorizers(listId, _asSingletonArray(account));
        assertTrue(validator.isAccountAuthorizer(listId, account));
    }

    function testRevertsWhenUnauthorizedUserAddsAccountToAuthorizerList(
        address listOwner,
        address unauthorizedUser,
        address account
    ) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        _sanitizeAddress(account);
        vm.assume(listOwner != unauthorizedUser);

        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addAccountsToAuthorizers(listId, _asSingletonArray(account));
    }

    function testAddAccountsToAuthorizerList(address listOwner, uint256 numAccountsToAuthorize, address[10] memory accounts) public {
        _sanitizeAddress(listOwner);
        numAccountsToAuthorize = bound(numAccountsToAuthorize, 1, 10);

        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        uint256 expectedNumAccountsAuthorized = 0;
        address[] memory accountsToAuthorize = new address[](numAccountsToAuthorize);
        for (uint256 i = 0; i < numAccountsToAuthorize; i++) {
            bool firstTimeAccount = true;
            for (uint256 j = 0; j < i; j++) {
                if (accountsToAuthorize[j] == accounts[i]) {
                    firstTimeAccount = false;
                    break;
                }
            }

            accountsToAuthorize[i] = accounts[i];

            if (firstTimeAccount) {
                expectedNumAccountsAuthorized++;
                vm.expectEmit(true, true, true, true);
                emit AddedAccountToList(LIST_TYPE_AUTHORIZERS, listId, accounts[i]);
            }
        }

        vm.prank(listOwner);
        validator.addAccountsToAuthorizers(listId, accountsToAuthorize);

        for (uint256 i = 0; i < numAccountsToAuthorize; i++) {
            assertTrue(validator.isAccountAuthorizer(listId, accountsToAuthorize[i]));
        }

        address[] memory authorizerAccounts = validator.getAuthorizerAccounts(listId);
        assertEq(authorizerAccounts.length, expectedNumAccountsAuthorized);
    }

    function testRevertsWhenUnauthorizedUserAddsAccountsToAuthorizerList(
        address listOwner,
        address unauthorizedUser,
        uint256 numAccountsToAuthorize,
        address[10] memory accounts
    ) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);

        numAccountsToAuthorize = bound(numAccountsToAuthorize, 1, 10);

        address[] memory accountsToAuthorize = new address[](numAccountsToAuthorize);
        for (uint256 i = 0; i < numAccountsToAuthorize; i++) {
            accountsToAuthorize[i] = accounts[i];
        }

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addAccountsToAuthorizers(0, accountsToAuthorize);
    }

    function testRemoveAccountFromAuthorizerList(address listOwner, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account);

        vm.startPrank(listOwner);
        uint120 listId = validator.createList("test");
        validator.addAccountsToAuthorizers(listId, _asSingletonArray(account));

        vm.expectEmit(true, true, true, true);
        emit RemovedAccountFromList(LIST_TYPE_AUTHORIZERS, listId, account);

        validator.removeAccountsFromAuthorizers(listId, _asSingletonArray(account));
        assertFalse(validator.isAccountAuthorizer(listId, account));
        vm.stopPrank();
    }

    function testRevertsWhenUnauthorizedUserRemovesAccountFromAuthorizerList(
        address listOwner,
        address unauthorizedUser,
        address account
    ) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        _sanitizeAddress(account);
        vm.assume(listOwner != unauthorizedUser);

        vm.startPrank(listOwner);
        uint120 listId = validator.createList("test");
        validator.addAccountsToAuthorizers(listId, _asSingletonArray(account));
        vm.stopPrank();

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.removeAccountsFromAuthorizers(listId, _asSingletonArray(account));
    }

    function testRemoveAccountsFromAuthorizerList(address listOwner, uint256 numAccountsToRemove, address[10] memory accounts) public {
        _sanitizeAddress(listOwner);
        numAccountsToRemove = bound(numAccountsToRemove, 1, 10);

        vm.startPrank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accountsToAuthorize = new address[](10);
        for (uint256 i = 0; i < 10; i++) {
            accountsToAuthorize[i] = accounts[i];
        }

        validator.addAccountsToAuthorizers(listId, accountsToAuthorize);
        vm.stopPrank();

        uint256 numPreAuthorizedAccounts = validator.getAuthorizerAccounts(listId).length;

        uint256 expectedNumAccountsRemoved = 0;
        address[] memory accountsToRemove = new address[](numAccountsToRemove);
        for (uint256 i = 0; i < numAccountsToRemove; i++) {
            bool firstTimeAccount = true;
            for (uint256 j = 0; j < i; j++) {
                if (accountsToRemove[j] == accounts[i]) {
                    firstTimeAccount = false;
                    break;
                }
            }

            accountsToRemove[i] = accounts[i];

            if (firstTimeAccount) {
                expectedNumAccountsRemoved++;
                vm.expectEmit(true, true, true, true);
                emit RemovedAccountFromList(LIST_TYPE_AUTHORIZERS, listId, accounts[i]);
            }
        }

        vm.prank(listOwner);
        validator.removeAccountsFromAuthorizers(listId, accountsToRemove);

        for (uint256 i = 0; i < numAccountsToRemove; i++) {
            assertFalse(validator.isAccountAuthorizer(listId, accountsToRemove[i]));
        }

        address[] memory authorizerAccounts = validator.getAuthorizerAccounts(listId);
        assertEq(authorizerAccounts.length, numPreAuthorizedAccounts - expectedNumAccountsRemoved);
    }

    function testRevertsWhenUnauthorizedUserRemovesAccountsFromAuthorizerList(
        address listOwner,
        address unauthorizedUser,
        uint256 numAccountsToRemove,
        address[10] memory accounts
    ) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);

        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        numAccountsToRemove = bound(numAccountsToRemove, 1, 10);

        address[] memory accountsToRemove = new address[](numAccountsToRemove);
        for (uint256 i = 0; i < numAccountsToRemove; i++) {
            accountsToRemove[i] = accounts[i];
        }

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.removeAccountsFromAuthorizers(listId, accountsToRemove);
    }

    function testAddCodeHashesToBlacklist(address listOwner, uint256 numCodeHashesToBlacklist, bytes32[10] memory codeHashes) public {
        _sanitizeAddress(listOwner);
        numCodeHashesToBlacklist = bound(numCodeHashesToBlacklist, 1, 10);

        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        uint256 expectedNumCodeHashesBlacklisted = 0;
        bytes32[] memory codeHashesToBlacklist = new bytes32[](numCodeHashesToBlacklist);
        for (uint256 i = 0; i < numCodeHashesToBlacklist; i++) {
            bool firstTimeCodeHash = true;
            for (uint256 j = 0; j < i; j++) {
                if (codeHashesToBlacklist[j] == codeHashes[i]) {
                    firstTimeCodeHash = false;
                    break;
                }
            }

            codeHashesToBlacklist[i] = codeHashes[i];

            if (firstTimeCodeHash) {
                expectedNumCodeHashesBlacklisted++;
                vm.expectEmit(true, true, true, true);
                emit AddedCodeHashToList(LIST_TYPE_BLACKLIST, listId, codeHashes[i]);
            }
        }

        vm.prank(listOwner);
        validator.addCodeHashesToBlacklist(listId, codeHashesToBlacklist);

        for (uint256 i = 0; i < numCodeHashesToBlacklist; i++) {
            assertTrue(validator.isCodeHashBlacklisted(listId, codeHashesToBlacklist[i]));
        }

        bytes32[] memory blacklistedCodeHashes = validator.getBlacklistedCodeHashes(listId);
        assertEq(blacklistedCodeHashes.length, expectedNumCodeHashesBlacklisted);
    }

    function testRevertsWhenUnauthorizedUserAddsCodeHashesToBlacklist(
        address listOwner,
        address unauthorizedUser,
        uint256 numCodeHashesToBlacklist,
        bytes32[10] memory codeHashes
    ) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);

        numCodeHashesToBlacklist = bound(numCodeHashesToBlacklist, 1, 10);

        bytes32[] memory codeHashesToBlacklist = new bytes32[](numCodeHashesToBlacklist);
        for (uint256 i = 0; i < numCodeHashesToBlacklist; i++) {
            codeHashesToBlacklist[i] = codeHashes[i];
        }

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addCodeHashesToBlacklist(0, codeHashesToBlacklist);
    }

    function testRemoveCodeHashesFromBlacklist(address listOwner, uint256 numCodeHashesToRemove, bytes32[10] memory codeHashes) public {
        _sanitizeAddress(listOwner);
        numCodeHashesToRemove = bound(numCodeHashesToRemove, 1, 10);

        vm.startPrank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codeHashesToBlacklist = new bytes32[](10);
        for (uint256 i = 0; i < 10; i++) {
            codeHashesToBlacklist[i] = codeHashes[i];
        }

        validator.addCodeHashesToBlacklist(listId, codeHashesToBlacklist);
        vm.stopPrank();

        uint256 numPreBlacklistedCodeHashes = validator.getBlacklistedCodeHashes(listId).length;

        uint256 expectedNumCodeHashesRemoved = 0;
        bytes32[] memory codeHashesToRemove = new bytes32[](numCodeHashesToRemove);
        for (uint256 i = 0; i < numCodeHashesToRemove; i++) {
            bool firstTimeCodeHash = true;
            for (uint256 j = 0; j < i; j++) {
                if (codeHashesToRemove[j] == codeHashes[i]) {
                    firstTimeCodeHash = false;
                    break;
                }
            }

            codeHashesToRemove[i] = codeHashes[i];

            if (firstTimeCodeHash) {
                expectedNumCodeHashesRemoved++;
                vm.expectEmit(true, true, true, true);
                emit RemovedCodeHashFromList(LIST_TYPE_BLACKLIST, listId, codeHashes[i]);
            }
        }

        vm.prank(listOwner);
        validator.removeCodeHashesFromBlacklist(listId, codeHashesToRemove);

        for (uint256 i = 0; i < numCodeHashesToRemove; i++) {
            assertFalse(validator.isCodeHashBlacklisted(listId, codeHashesToRemove[i]));
        }

        bytes32[] memory blacklistedCodeHashes = validator.getBlacklistedCodeHashes(listId);
        assertEq(blacklistedCodeHashes.length, numPreBlacklistedCodeHashes - expectedNumCodeHashesRemoved);
    }

    function testRevertsWhenUnauthorizedUserRemovesCodeHashesFromBlacklist(
        address listOwner,
        address unauthorizedUser,
        uint256 numCodeHashesToRemove,
        bytes32[10] memory codeHashes
    ) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);

        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        numCodeHashesToRemove = bound(numCodeHashesToRemove, 1, 10);

        bytes32[] memory codeHashesToRemove = new bytes32[](numCodeHashesToRemove);
        for (uint256 i = 0; i < numCodeHashesToRemove; i++) {
            codeHashesToRemove[i] = codeHashes[i];
        }

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.removeCodeHashesFromBlacklist(listId, codeHashesToRemove);
    }

    function testAddCodeHashesToWhitelist(address listOwner, uint256 numCodeHashesToWhitelist, bytes32[10] memory codeHashes) public {
        _sanitizeAddress(listOwner);
        numCodeHashesToWhitelist = bound(numCodeHashesToWhitelist, 1, 10);

        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        uint256 expectedNumCodeHashesWhitelisted = 0;
        bytes32[] memory codeHashesToWhitelist = new bytes32[](numCodeHashesToWhitelist);
        for (uint256 i = 0; i < numCodeHashesToWhitelist; i++) {
            bool firstTimeCodeHash = true;
            for (uint256 j = 0; j < i; j++) {
                if (codeHashesToWhitelist[j] == codeHashes[i]) {
                    firstTimeCodeHash = false;
                    break;
                }
            }

            codeHashesToWhitelist[i] = codeHashes[i];

            if (firstTimeCodeHash) {
                expectedNumCodeHashesWhitelisted++;
                vm.expectEmit(true, true, true, true);
                emit AddedCodeHashToList(LIST_TYPE_WHITELIST, listId, codeHashes[i]);
            }
        }

        vm.prank(listOwner);
        validator.addCodeHashesToWhitelist(listId, codeHashesToWhitelist);

        for (uint256 i = 0; i < numCodeHashesToWhitelist; i++) {
            assertTrue(validator.isCodeHashWhitelisted(listId, codeHashesToWhitelist[i]));
        }

        bytes32[] memory whitelistedCodeHashes = validator.getWhitelistedCodeHashes(listId);
        assertEq(whitelistedCodeHashes.length, expectedNumCodeHashesWhitelisted);
    }

    function testRevertsWhenUnauthorizedUserAddsCodeHashesToWhitelist(
        address listOwner,
        address unauthorizedUser,
        uint256 numCodeHashesToWhitelist,
        bytes32[10] memory codeHashes
    ) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);

        numCodeHashesToWhitelist = bound(numCodeHashesToWhitelist, 1, 10);

        bytes32[] memory codeHashesToWhitelist = new bytes32[](numCodeHashesToWhitelist);
        for (uint256 i = 0; i < numCodeHashesToWhitelist; i++) {
            codeHashesToWhitelist[i] = codeHashes[i];
        }

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addCodeHashesToWhitelist(0, codeHashesToWhitelist);
    }

    function testRemoveCodeHashesFromWhitelist(address listOwner, uint256 numCodeHashesToRemove, bytes32[10] memory codeHashes) public {
        _sanitizeAddress(listOwner);
        numCodeHashesToRemove = bound(numCodeHashesToRemove, 1, 10);

        vm.startPrank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codeHashesToWhitelist = new bytes32[](10);
        for (uint256 i = 0; i < 10; i++) {
            codeHashesToWhitelist[i] = codeHashes[i];
        }

        validator.addCodeHashesToWhitelist(listId, codeHashesToWhitelist);
        vm.stopPrank();

        uint256 numPreWhitelistedCodeHashes = validator.getWhitelistedCodeHashes(listId).length;

        uint256 expectedNumCodeHashesRemoved = 0;
        bytes32[] memory codeHashesToRemove = new bytes32[](numCodeHashesToRemove);
        for (uint256 i = 0; i < numCodeHashesToRemove; i++) {
            bool firstTimeCodeHash = true;
            for (uint256 j = 0; j < i; j++) {
                if (codeHashesToRemove[j] == codeHashes[i]) {
                    firstTimeCodeHash = false;
                    break;
                }
            }

            codeHashesToRemove[i] = codeHashes[i];

            if (firstTimeCodeHash) {
                expectedNumCodeHashesRemoved++;
                vm.expectEmit(true, true, true, true);
                emit RemovedCodeHashFromList(LIST_TYPE_WHITELIST, listId, codeHashes[i]);
            }
        }

        vm.prank(listOwner);
        validator.removeCodeHashesFromWhitelist(listId, codeHashesToRemove);

        for (uint256 i = 0; i < numCodeHashesToRemove; i++) {
            assertFalse(validator.isCodeHashWhitelisted(listId, codeHashesToRemove[i]));
        }

        bytes32[] memory whitelistedCodeHashes = validator.getWhitelistedCodeHashes(listId);
        assertEq(whitelistedCodeHashes.length, numPreWhitelistedCodeHashes - expectedNumCodeHashesRemoved);
    }

    function testRevertsWhenUnauthorizedUserRemovesCodeHashesFromWhitelist(
        address listOwner,
        address unauthorizedUser,
        uint256 numCodeHashesToRemove,
        bytes32[10] memory codeHashes
    ) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);

        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        numCodeHashesToRemove = bound(numCodeHashesToRemove, 1, 10);

        bytes32[] memory codeHashesToRemove = new bytes32[](numCodeHashesToRemove);
        for (uint256 i = 0; i < numCodeHashesToRemove; i++) {
            codeHashesToRemove[i] = codeHashes[i];
        }

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.removeCodeHashesFromWhitelist(listId, codeHashesToRemove);
    }

    // Validation of Transfers Level 1

    struct FuzzedList {
        address whitelistedAddress;
        address whitelistedToAddress;
        address blacklistedAddress;
        address authorizerAddress;
        bytes32 whitelistedCode;
        bytes32 blacklistedCode;
    }

    function testAllowsAllTransfersAtLevelOne(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        _configureCollectionSecurity(
            collection, 
            fuzzedList, 
            TRANSFER_SECURITY_LEVEL_ONE, 
            disableAuthorizationMode, 
            authorizersCannotSetWildcardOperators, 
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey,
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    // Validation of Transfers Level 2

    function testAllowsAllTransfersAtLevelTwoWhenCallerIsNotBlacklisted(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(fuzzedList.blacklistedAddress != caller);

        _configureCollectionSecurity(
            collection, 
            fuzzedList, 
            TRANSFER_SECURITY_LEVEL_TWO, 
            disableAuthorizationMode, 
            authorizersCannotSetWildcardOperators, 
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testRevertsAllTransfersAtLevelTwoWhenCallerIsBlacklistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.blacklistedAddress;

        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(caller != from);

        _configureCollectionSecurity(
            collection, 
            fuzzedList, 
            TRANSFER_SECURITY_LEVEL_TWO, 
            disableAuthorizationMode, 
            authorizersCannotSetWildcardOperators, 
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount, 
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__OperatorIsBlacklisted.selector
        );
    }

    function testRevertsAllTransfersAtLevelTwoWhenCallerIsBlacklistedCodeHash(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(caller != from);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, true);
        _etchCodeToCaller(caller, fuzzedList.blacklistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList, 
            TRANSFER_SECURITY_LEVEL_TWO, 
            disableAuthorizationMode, 
            authorizersCannotSetWildcardOperators, 
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount, 
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__OperatorIsBlacklisted.selector
        );
    }

    function testAllowsAuthorizedTransfersAtLevelTwoWhenCallerIsBlacklistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.blacklistedAddress;
        address authorizer = fuzzedList.authorizerAddress;

        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        _sanitizeAddress(authorizer);
        vm.assume(caller != from);

        _configureCollectionSecurity(
            collection, 
            fuzzedList, 
            TRANSFER_SECURITY_LEVEL_TWO, 
            false, 
            false, 
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer, 
            caller, 
            collection, 
            tokenId, 
            amount, 
            SELECTOR_NO_ERROR
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount, 
            SELECTOR_NO_ERROR
        );
    }

    // Validation of Transfers Level 3

    function testAllowsAllTransfersAtLevelThreeWhenCallerIsWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_THREE,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsAllTransfersAtLevelThreeWhenCallerIsWhitelistedCodeHash(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, false);
        _etchCodeToCaller(caller, fuzzedList.whitelistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_THREE,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsOTCTransfersAtLevelThree(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, from, from, to);
        vm.assume(from != fuzzedList.whitelistedAddress);
        vm.assume(from != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_THREE,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            from, 
            from,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testRevertsAllTransfersAtLevelThreeWhenCallerIsNotWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(caller != from);
        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_THREE,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector
        );
    }

    function testAllowsAuthorizedTransfersAtLevelThreeWhenCallerIsNotWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool enableAccountFreezingMode
    ) public {
        address authorizer = fuzzedList.authorizerAddress;
        
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        _sanitizeAddress(authorizer);

        vm.assume(caller != from);
        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_THREE,
            false,
            false,
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer, 
            caller, 
            collection, 
            tokenId, 
            amount, 
            SELECTOR_NO_ERROR
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    // Validation of Transfers Level 4

    function testAllowsAllTransfersAtLevelFourWhenCallerIsWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(caller != from);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FOUR,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsAllTransfersAtLevelFourWhenFromIsWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address from = fuzzedList.whitelistedAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        fuzzedList.whitelistedAddress = from;
        vm.assume(caller != from);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FOUR,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsAllTransfersAtLevelFourWhenCallerIsWhitelistedCodeHash(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(caller != from);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, false);
        _etchCodeToCaller(caller, fuzzedList.whitelistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FOUR,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsAllTransfersAtLevelFourWhenFromIsWhitelistedCodeHash(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(caller != from);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, false);
        _etchCodeToCaller(from, fuzzedList.whitelistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FOUR,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testRevertsOTCTransfersAtLevelFour(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = from;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FOUR,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector
        );
    }

    function testRevertsAllTransfersAtLevelFourWhenCallerIsNotWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);
        vm.assume(from != fuzzedList.whitelistedAddress);
        vm.assume(from != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FOUR,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector
        );
    }

    function testAllowsAuthorizedOTCTransfersAtLevelFour(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool enableAccountFreezingMode
    ) public {
        address caller = from;
        address authorizer = fuzzedList.authorizerAddress;

        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        _sanitizeAddress(authorizer);
        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FOUR,
            false,
            false,
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer, 
            caller, 
            collection, 
            tokenId, 
            amount, 
            SELECTOR_NO_ERROR
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsAuthorizedTransfersAtLevelFourWhenCallerIsNotWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool enableAccountFreezingMode
    ) public {
        address authorizer = fuzzedList.authorizerAddress;

        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        _sanitizeAddress(authorizer);
        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FOUR,
            false,
            false,
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer, 
            caller, 
            collection, 
            tokenId, 
            amount, 
            SELECTOR_NO_ERROR
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    // Validation of Transfers Level 5

    function testAllowsAllTransfersAtLevelFiveWhenCallerIsWhitelistedAccountAndReceiverHasNoCode(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FIVE,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsTransfersAtLevelFiveWhenReceiverHashCodeButAccountIsWhitelisted(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, false);
        _etchCodeToCaller(to, fuzzedList.whitelistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FIVE,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsTransfersAtLevelFiveWhenReceiverHashCodeButCodeHashIsWhitelisted(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(to != fuzzedList.whitelistedAddress);
        vm.assume(to != fuzzedList.whitelistedToAddress);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, false);
        _etchCodeToCaller(to, fuzzedList.whitelistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FIVE,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testRevertsTransfersAtLevelFiveWhenReceiverHasCode(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(to != fuzzedList.whitelistedAddress);
        vm.assume(to != fuzzedList.whitelistedToAddress);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, true);
        _etchCodeToCaller(to, fuzzedList.blacklistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FIVE,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__ReceiverMustNotHaveDeployedCode.selector
        );
    }

    function testAllowsAllTransfersAtLevelFiveWhenCallerIsWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FIVE,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsAllTransfersAtLevelFiveWhenCallerIsWhitelistedCodeHash(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, false);
        _etchCodeToCaller(caller, fuzzedList.whitelistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FIVE,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsOTCTransfersAtLevelFive(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, from, from, to);
        vm.assume(from != fuzzedList.whitelistedAddress);
        vm.assume(from != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FIVE,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            from, 
            from,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testRevertsAllTransfersAtLevelFiveWhenCallerIsNotWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(caller != from);
        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FIVE,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector
        );
    }

    function testAllowsAuthorizedTransfersAtLevelFiveWhenReceiverHasCode(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        address authorizer = fuzzedList.authorizerAddress;
        
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        _sanitizeAddress(authorizer);

        vm.assume(to != fuzzedList.whitelistedAddress);
        vm.assume(to != fuzzedList.whitelistedToAddress);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, false);
        _etchCodeToCaller(to, fuzzedList.whitelistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FIVE,
            false,
            false,
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer, 
            caller, 
            collection, 
            tokenId, 
            amount, 
            SELECTOR_NO_ERROR
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsAuthorizedTransfersAtLevelFiveWhenCallerIsNotWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool enableAccountFreezingMode
    ) public {
        address to = fuzzedList.whitelistedToAddress;
        address authorizer = fuzzedList.authorizerAddress;

        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        _sanitizeAddress(authorizer);

        vm.assume(caller != from);
        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_FIVE,
            false,
            false,
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer, 
            caller, 
            collection, 
            tokenId, 
            amount, 
            SELECTOR_NO_ERROR
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    // Validation of Transfers Level 6

    function testAllowsAllTransfersAtLevelSixWhenCallerIsWhitelistedAccountAndReceiverIsVerifiedEOA(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        uint160 toKey,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address to = _verifyEOA(toKey);
        address caller = fuzzedList.whitelistedAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SIX,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsTransfersAtLevelSixWhenReceiverIsNotAVerifiedEOAButAccountIsWhitelisted(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SIX,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsTransfersAtLevelSixWhenReceiverIsNotVerifiedEOAButCodeHashIsWhitelisted(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(to != fuzzedList.whitelistedAddress);
        vm.assume(to != fuzzedList.whitelistedToAddress);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, false);
        _etchCodeToCaller(to, fuzzedList.whitelistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SIX,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testRevertsTransfersAtLevelSixWhenReceiverHasNotVerifiedThatTheyAreAnEOA(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(to != fuzzedList.whitelistedAddress);
        vm.assume(to != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SIX,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__ReceiverProofOfEOASignatureUnverified.selector
        );
    }

    function testAllowsAllTransfersAtLevelSixWhenCallerIsWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SIX,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsAllTransfersAtLevelSixWhenCallerIsWhitelistedCodeHash(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, false);
        _etchCodeToCaller(caller, fuzzedList.whitelistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SIX,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsOTCTransfersAtLevelSix(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, from, from, to);
        vm.assume(from != fuzzedList.whitelistedAddress);
        vm.assume(from != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SIX,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            from, 
            from,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testRevertsAllTransfersAtLevelSixWhenCallerIsNotWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(caller != from);
        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SIX,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector
        );
    }

    function testAllowsAuthorizedTransfersAtLevelSixWhenReceiverHasNotVerifiedThatTheyAreAnEOA(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        address authorizer = fuzzedList.authorizerAddress;

        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        _sanitizeAddress(authorizer);

        vm.assume(to != fuzzedList.whitelistedAddress);
        vm.assume(to != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SIX,
            false,
            false,
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer, 
            caller, 
            collection, 
            tokenId, 
            amount, 
            SELECTOR_NO_ERROR
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsAuthorizedTransfersAtLevelSixWhenCallerIsNotWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool enableAccountFreezingMode
    ) public {
        address to = fuzzedList.whitelistedToAddress;
        address authorizer = fuzzedList.authorizerAddress;

        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(caller != from);
        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SIX,
            false,
            false,
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer, 
            caller, 
            collection, 
            tokenId, 
            amount, 
            SELECTOR_NO_ERROR
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    // Validation of Transfers Level 7

    function testAllowsAllTransfersAtLevelSevenWhenCallerIsWhitelistedAccountAndReceiverHasNoCode(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SEVEN,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsTransfersAtLevelSevenWhenReceiverHashCodeButAccountIsWhitelisted(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, false);
        _etchCodeToCaller(to, fuzzedList.whitelistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SEVEN,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsTransfersAtLevelSevenWhenReceiverHashCodeButCodeHashIsWhitelisted(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(to != fuzzedList.whitelistedAddress);
        vm.assume(to != fuzzedList.whitelistedToAddress);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, false);
        _etchCodeToCaller(to, fuzzedList.whitelistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SEVEN,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testRevertsTransfersAtLevelSevenWhenReceiverHasCode(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(to != fuzzedList.whitelistedAddress);
        vm.assume(to != fuzzedList.whitelistedToAddress);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, true);
        _etchCodeToCaller(to, fuzzedList.blacklistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SEVEN,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__ReceiverMustNotHaveDeployedCode.selector
        );
    }

    function testAllowsAllTransfersAtLevelSevenWhenCallerIsWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SEVEN,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsAllTransfersAtLevelSevenWhenCallerIsWhitelistedCodeHash(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, false);
        _etchCodeToCaller(caller, fuzzedList.whitelistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SEVEN,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testRevertsOTCTransfersAtLevelSeven(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = from;
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SEVEN,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector
        );
    }

    function testRevertsAllTransfersAtLevelSevenWhenCallerIsNotWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(caller != from);
        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);
        vm.assume(from != fuzzedList.whitelistedAddress);
        vm.assume(from != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SEVEN,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector
        );
    }

    function testAllowsAuthorizedTransfersAtLevelSevenWhenReceiverHasCode(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        address authorizer = fuzzedList.authorizerAddress;

        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        _sanitizeAddress(authorizer);

        vm.assume(to != fuzzedList.whitelistedAddress);
        vm.assume(to != fuzzedList.whitelistedToAddress);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, false);
        _etchCodeToCaller(to, fuzzedList.whitelistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SEVEN,
            false,
            false,
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer, 
            caller, 
            collection, 
            tokenId, 
            amount, 
            SELECTOR_NO_ERROR
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsAuthorizedOTCTransfersAtLevelSeven(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool enableAccountFreezingMode
    ) public {
        address caller = from;
        address to = fuzzedList.whitelistedToAddress;
        address authorizer = fuzzedList.authorizerAddress;

        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        _sanitizeAddress(authorizer);

        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SEVEN,
            false,
            false,
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer, 
            caller, 
            collection, 
            tokenId, 
            amount, 
            SELECTOR_NO_ERROR
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsAuthorizedTransfersAtLevelSevenWhenCallerIsNotWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool enableAccountFreezingMode
    ) public {
        address to = fuzzedList.whitelistedToAddress;
        address authorizer = fuzzedList.authorizerAddress;

        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        _sanitizeAddress(authorizer);

        vm.assume(caller != from);
        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_SEVEN,
            false,
            false,
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer, 
            caller, 
            collection, 
            tokenId, 
            amount, 
            SELECTOR_NO_ERROR
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    // Validation of Transfers Level 8

    function testAllowsAllTransfersAtLevelEightWhenCallerIsWhitelistedAccountAndReceiverIsVerifiedEOA(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        uint160 toKey,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address to = _verifyEOA(toKey);
        address caller = fuzzedList.whitelistedAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_EIGHT,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsTransfersAtLevelEightWhenReceiverIsNotAVerifiedEOAButAccountIsWhitelisted(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_EIGHT,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsTransfersAtLevelEightWhenReceiverIsNotVerifiedEOAButCodeHashIsWhitelisted(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(to != fuzzedList.whitelistedAddress);
        vm.assume(to != fuzzedList.whitelistedToAddress);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, false);
        _etchCodeToCaller(to, fuzzedList.whitelistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_EIGHT,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testRevertsTransfersAtLevelEightWhenReceiverHasNotVerifiedThatTheyAreAnEOA(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(to != fuzzedList.whitelistedAddress);
        vm.assume(to != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_EIGHT,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__ReceiverProofOfEOASignatureUnverified.selector
        );
    }

    function testAllowsAllTransfersAtLevelEightWhenCallerIsWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_EIGHT,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsAllTransfersAtLevelEightWhenCallerIsWhitelistedCodeHash(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        (fuzzedList.whitelistedCode, fuzzedList.blacklistedCode) = _sanitizeCode(fuzzedList.whitelistedCode, fuzzedList.blacklistedCode, false);
        _etchCodeToCaller(caller, fuzzedList.whitelistedCode);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_EIGHT,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testRevertsOTCTransfersAtLevelEight(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address caller = from;
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_EIGHT,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector
        );
    }

    function testRevertsAllTransfersAtLevelEightWhenCallerIsNotWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address to = fuzzedList.whitelistedToAddress;
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);
        vm.assume(from != fuzzedList.whitelistedAddress);
        vm.assume(from != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_EIGHT,
            disableAuthorizationMode,
            authorizersCannotSetWildcardOperators,
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector
        );
    }

    function testAllowsAuthorizedTransfersAtLevelEightWhenReceiverHasNotVerifiedThatTheyAreAnEOA(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool enableAccountFreezingMode
    ) public {
        address caller = fuzzedList.whitelistedAddress;
        address authorizer = fuzzedList.authorizerAddress;

        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        _sanitizeAddress(authorizer);

        vm.assume(to != fuzzedList.whitelistedAddress);
        vm.assume(to != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_EIGHT,
            false,
            false,
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer, 
            caller, 
            collection, 
            tokenId, 
            amount, 
            SELECTOR_NO_ERROR
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsAuthorizedOTCTransfersAtLevelEight(
        FuzzedList memory fuzzedList,
        address collection,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool enableAccountFreezingMode
    ) public {
        address caller = from;
        address to = fuzzedList.whitelistedToAddress;
        address authorizer = fuzzedList.authorizerAddress;

        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        _sanitizeAddress(authorizer);

        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_EIGHT,
            false,
            false,
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer, 
            caller, 
            collection, 
            tokenId, 
            amount, 
            SELECTOR_NO_ERROR
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testAllowsAuthorizedTransfersAtLevelEightWhenCallerIsNotWhitelistedAccount(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        uint256 tokenId,
        uint256 amount,
        bool enableAccountFreezingMode
    ) public {
        address to = fuzzedList.whitelistedToAddress;
        address authorizer = fuzzedList.authorizerAddress;

        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        _sanitizeAddress(authorizer);

        vm.assume(caller != fuzzedList.whitelistedAddress);
        vm.assume(caller != fuzzedList.whitelistedToAddress);

        _configureCollectionSecurity(
            collection, 
            fuzzedList,
            TRANSFER_SECURITY_LEVEL_EIGHT,
            false,
            false,
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer, 
            caller, 
            collection, 
            tokenId, 
            amount, 
            SELECTOR_NO_ERROR
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    // Validation of Transfers Level 9

    function testRevertsAllTransfersAtLevelNine(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        _configureCollectionSecurity(
            collection, 
            fuzzedList, 
            TRANSFER_SECURITY_LEVEL_NINE, 
            disableAuthorizationMode, 
            authorizersCannotSetWildcardOperators, 
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount, 
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__TokenIsSoulbound.selector
        );
    }

    // All Security Levels

    function testAllowsAllTransfersWhereCallerIsTransferValidator(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        uint8 transferSecurityLevel,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);

        transferSecurityLevel = uint8(bound(transferSecurityLevel, TRANSFER_SECURITY_LEVEL_RECOMMENDED, TRANSFER_SECURITY_LEVEL_NINE));

        _freezeAccount(collection, from);
        _freezeAccount(collection, to);

        _configureCollectionSecurity(
            collection, 
            fuzzedList, 
            transferSecurityLevel, 
            disableAuthorizationMode, 
            authorizersCannotSetWildcardOperators, 
            enableAccountFreezingMode
        );

        _validateTransfersWithExpectedRevert(
            collection, 
            address(validator),
            address(validator),
            fromKey,
            from, 
            to, 
            tokenId, 
            amount,
            SELECTOR_NO_ERROR
        );
    }

    function testRevertsTransfersFromFrozenAccountsAtAllSecurityLevels(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        uint8 transferSecurityLevel,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators
    ) public {
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(from != to);

        transferSecurityLevel = uint8(bound(transferSecurityLevel, TRANSFER_SECURITY_LEVEL_RECOMMENDED, TRANSFER_SECURITY_LEVEL_EIGHT));

        _configureCollectionSecurity(
            collection, 
            fuzzedList, 
            transferSecurityLevel, 
            disableAuthorizationMode, 
            authorizersCannotSetWildcardOperators, 
            true
        );

        _freezeAccount(collection, from);

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount, 
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__SenderAccountIsFrozen.selector
        );
    }

    function testRevertsTransfersToFrozenAccountsAtAllSecurityLevels(
        FuzzedList memory fuzzedList,
        address collection,
        address caller,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        uint8 transferSecurityLevel,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators
    ) public {
        uint256 fromKey;
        (collection, from, fromKey) = _sanitizeAccounts(collection, caller, from, to);
        vm.assume(from != to);

        transferSecurityLevel = uint8(bound(transferSecurityLevel, TRANSFER_SECURITY_LEVEL_RECOMMENDED, TRANSFER_SECURITY_LEVEL_EIGHT));

        _configureCollectionSecurity(
            collection, 
            fuzzedList, 
            transferSecurityLevel, 
            disableAuthorizationMode, 
            authorizersCannotSetWildcardOperators, 
            true
        );

        _freezeAccount(collection, to);

        _validateTransfersWithExpectedRevert(
            collection, 
            caller, 
            caller,
            fromKey, 
            from, 
            to, 
            tokenId, 
            amount, 
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__ReceiverAccountIsFrozen.selector
        );
    }

    // Authorization Mode

    function testAllowsBeforeAuthorizedTransferWhenAuthorizationModeIsEnabledAndAuthorizerIsAllowed(
        FuzzedList memory fuzzedList,
        address collection,
        address operator,
        uint256 tokenId, 
        uint256 amount,
        uint8 transferSecurityLevel,
        bool enableAccountFreezingMode
    ) public {
        address authorizer = fuzzedList.authorizerAddress;
        uint256 fromKey;
        (collection, operator, fromKey) = _sanitizeAccounts(collection, authorizer, operator, operator);
        transferSecurityLevel = uint8(bound(transferSecurityLevel, TRANSFER_SECURITY_LEVEL_RECOMMENDED, TRANSFER_SECURITY_LEVEL_NINE));
        _configureCollectionSecurity(
            collection, 
            fuzzedList, 
            transferSecurityLevel, 
            false, 
            false, 
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer,
            operator, 
            collection, 
            tokenId, 
            amount, 
            SELECTOR_NO_ERROR
        );
    }

    function testRevertsBeforeAuthorizedTransferWhenAuthorizationModeIsDisabled(
        FuzzedList memory fuzzedList,
        address collection,
        address operator,
        uint256 tokenId, 
        uint256 amount,
        uint8 transferSecurityLevel,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address authorizer = fuzzedList.authorizerAddress;
        uint256 fromKey;
        (collection, operator, fromKey) = _sanitizeAccounts(collection, authorizer, operator, operator);
        transferSecurityLevel = uint8(bound(transferSecurityLevel, TRANSFER_SECURITY_LEVEL_RECOMMENDED, TRANSFER_SECURITY_LEVEL_NINE));
        _configureCollectionSecurity(
            collection, 
            fuzzedList, 
            transferSecurityLevel, 
            true, 
            authorizersCannotSetWildcardOperators, 
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer,
            operator, 
            collection, 
            tokenId, 
            amount, 
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__AuthorizationDisabledForCollection.selector
        );
    }

    function testRevertsBeforeAuthorizedTransferWhenAuthorizationModeIsEnabledButWildcardOperatorIsUsedAndWildcardOperatorsAreDisabled(
        FuzzedList memory fuzzedList,
        address collection,
        uint256 tokenId, 
        uint256 amount,
        uint8 transferSecurityLevel,
        bool enableAccountFreezingMode
    ) public {
        address authorizer = fuzzedList.authorizerAddress;
        address operator = address(0x01);
        uint256 fromKey;
        (collection, authorizer, fromKey) = _sanitizeAccounts(collection, authorizer, authorizer, authorizer);
        transferSecurityLevel = uint8(bound(transferSecurityLevel, TRANSFER_SECURITY_LEVEL_RECOMMENDED, TRANSFER_SECURITY_LEVEL_NINE));
        _configureCollectionSecurity(
            collection, 
            fuzzedList, 
            transferSecurityLevel, 
            false, 
            true, 
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer,
            operator, 
            collection, 
            tokenId, 
            amount, 
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__WildcardOperatorsCannotBeAuthorizedForCollection.selector
        );
    }

    function testRevertsBeforeAuthorizedTransferWhenAuthorizationModeIsEnabledButTheCallerIsNotInTheAuthorizerList(
        FuzzedList memory fuzzedList,
        address authorizer,
        address collection,
        address operator,
        uint256 tokenId, 
        uint256 amount,
        uint8 transferSecurityLevel,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        uint256 fromKey;
        (collection, operator, fromKey) = _sanitizeAccounts(collection, authorizer, operator, operator);
        vm.assume(authorizer != fuzzedList.authorizerAddress);

        transferSecurityLevel = uint8(bound(transferSecurityLevel, TRANSFER_SECURITY_LEVEL_RECOMMENDED, TRANSFER_SECURITY_LEVEL_NINE));
        _configureCollectionSecurity(
            collection, 
            fuzzedList, 
            transferSecurityLevel, 
            false, 
            false, 
            enableAccountFreezingMode
        );

        _beforeAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer,
            operator, 
            collection, 
            tokenId, 
            amount, 
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustBeAnAuthorizer.selector
        );
    }

    function testAllowsAfterAuthorizedTransferWhenAuthorizationModeIsEnabledAndAuthorizerIsAllowed(
        FuzzedList memory fuzzedList,
        address collection,
        address operator,
        uint256 tokenId, 
        uint256 amount,
        uint8 transferSecurityLevel,
        bool enableAccountFreezingMode
    ) public {
        address authorizer = fuzzedList.authorizerAddress;
        uint256 fromKey;
        (collection, operator, fromKey) = _sanitizeAccounts(collection, authorizer, operator, operator);
        transferSecurityLevel = uint8(bound(transferSecurityLevel, TRANSFER_SECURITY_LEVEL_RECOMMENDED, TRANSFER_SECURITY_LEVEL_NINE));
        _configureCollectionSecurity(
            collection, 
            fuzzedList, 
            transferSecurityLevel, 
            false, 
            false, 
            enableAccountFreezingMode
        );

        _afterAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer,
            operator, 
            collection, 
            tokenId, 
            SELECTOR_NO_ERROR
        );
    }

    function testRevertsAfterAuthorizedTransferWhenAuthorizationModeIsDisabled(
        FuzzedList memory fuzzedList,
        address collection,
        address operator,
        uint256 tokenId, 
        uint256 amount,
        uint8 transferSecurityLevel,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address authorizer = fuzzedList.authorizerAddress;
        uint256 fromKey;
        (collection, operator, fromKey) = _sanitizeAccounts(collection, authorizer, operator, operator);
        transferSecurityLevel = uint8(bound(transferSecurityLevel, TRANSFER_SECURITY_LEVEL_RECOMMENDED, TRANSFER_SECURITY_LEVEL_NINE));
        _configureCollectionSecurity(
            collection, 
            fuzzedList, 
            transferSecurityLevel, 
            true, 
            authorizersCannotSetWildcardOperators, 
            enableAccountFreezingMode
        );

        _afterAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer,
            operator, 
            collection, 
            tokenId, 
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__AuthorizationDisabledForCollection.selector
        );
    }

    function testRevertsAfterAuthorizedTransferWhenAuthorizationModeIsEnabledButTheCallerIsNotInTheAuthorizerList(
        FuzzedList memory fuzzedList,
        address authorizer,
        address collection,
        address operator,
        uint256 tokenId, 
        uint256 amount,
        uint8 transferSecurityLevel,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        uint256 fromKey;
        (collection, operator, fromKey) = _sanitizeAccounts(collection, authorizer, operator, operator);
        vm.assume(authorizer != fuzzedList.authorizerAddress);

        transferSecurityLevel = uint8(bound(transferSecurityLevel, TRANSFER_SECURITY_LEVEL_RECOMMENDED, TRANSFER_SECURITY_LEVEL_NINE));
        _configureCollectionSecurity(
            collection, 
            fuzzedList, 
            transferSecurityLevel, 
            false, 
            false, 
            enableAccountFreezingMode
        );

        _afterAuthorizedTransferCallsWithExpectedRevert(
            authorizer, 
            authorizer,
            operator, 
            collection, 
            tokenId, 
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustBeAnAuthorizer.selector
        );
    }

    function testAuthorizationModeRevertsWhenTransferringATokenIdThatWasNotAuthorized(
        address alice,
        address bob,
        uint256 firstTokenId,
        uint256 secondTokenId
    ) external {
        _sanitizeAddress(alice);
        _sanitizeAddress(bob);

        vm.assume(alice != bob);
        vm.assume(firstTokenId != 0);
        vm.assume(secondTokenId != 0);
        vm.assume(firstTokenId != secondTokenId);

        ERC721CMock token = new ERC721CMock();
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection({
            collection: address(token),
            level: TRANSFER_SECURITY_LEVEL_RECOMMENDED,
            disableAuthorizationMode: false,
            disableWildcardOperators: true,
            enableAccountFreezingMode: false
        });

        uint120 listId = validator.createList("");
        validator.applyListToCollection(address(token), listId);
        address[] memory authorizers = new address[](1);
        authorizers[0] = address(this);
        validator.addAccountsToAuthorizers(listId, authorizers);

        OperatorMock operator = new OperatorMock();
        token.mint(alice, firstTokenId);
        token.mint(alice, secondTokenId);

        vm.prank(alice);
        token.setApprovalForAll(address(operator), true);
        /// @dev Enable the operator to transfer the `firstTokenId`.
        validator.beforeAuthorizedTransfer(address(operator), address(token), firstTokenId);
        operator.tokenTransferFrom(address(token), alice, bob, firstTokenId);

        /// @dev Operator should *not* be able to transfer `secondTokenId`.
        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector);
        operator.tokenTransferFrom(address(token), alice, bob, secondTokenId);
    }

    function testAuthorizationModeSucceedsWhenTransferringTokenIdsThatWereAuthorized(
        address alice,
        address bob,
        uint256 firstTokenId,
        uint256 secondTokenId
    ) external {
        _sanitizeAddress(alice);
        _sanitizeAddress(bob);

        vm.assume(alice != bob);
        vm.assume(firstTokenId != 0);
        vm.assume(secondTokenId != 0);
        vm.assume(firstTokenId != secondTokenId);

        ERC721CMock token = new ERC721CMock();
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection({
            collection: address(token),
            level: TRANSFER_SECURITY_LEVEL_RECOMMENDED,
            disableAuthorizationMode: false,
            disableWildcardOperators: true,
            enableAccountFreezingMode: false
        });

        uint120 listId = validator.createList("");
        validator.applyListToCollection(address(token), listId);
        address[] memory authorizers = new address[](1);
        authorizers[0] = address(this);
        validator.addAccountsToAuthorizers(listId, authorizers);

        OperatorMock operator = new OperatorMock();
        token.mint(alice, firstTokenId);
        token.mint(alice, secondTokenId);

        vm.prank(alice);
        token.setApprovalForAll(address(operator), true);
        /// @dev Enable the operator to transfer the `firstTokenId`.
        validator.beforeAuthorizedTransfer(address(operator), address(token), firstTokenId);
        operator.tokenTransferFrom(address(token), alice, bob, firstTokenId);

        /// @dev Enable the operator to transfer the `secondTokenId`.
        validator.beforeAuthorizedTransfer(address(operator), address(token), secondTokenId);
        operator.tokenTransferFrom(address(token), alice, bob, secondTokenId);
    }

    function testAuthorizationModeSucceedsWhenTransferringTokenIdsWhenAllTokensAreAuthorized(
        address alice,
        address bob,
        uint256 firstTokenId,
        uint256 secondTokenId
    ) external {
        _sanitizeAddress(alice);
        _sanitizeAddress(bob);

        vm.assume(alice != bob);
        vm.assume(firstTokenId != 0);
        vm.assume(secondTokenId != 0);
        vm.assume(firstTokenId != secondTokenId);

        ERC721CMock token = new ERC721CMock();
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection({
            collection: address(token),
            level: TRANSFER_SECURITY_LEVEL_RECOMMENDED,
            disableAuthorizationMode: false,
            disableWildcardOperators: true,
            enableAccountFreezingMode: false
        });

        uint120 listId = validator.createList("");
        validator.applyListToCollection(address(token), listId);
        address[] memory authorizers = new address[](1);
        authorizers[0] = address(this);
        validator.addAccountsToAuthorizers(listId, authorizers);

        OperatorMock operator = new OperatorMock();
        token.mint(alice, firstTokenId);
        token.mint(alice, secondTokenId);

        vm.prank(alice);
        token.setApprovalForAll(address(operator), true);
        /// @dev Enable the operator to transfer all tokens.
        validator.beforeAuthorizedTransfer(address(operator), address(token));
        operator.tokenTransferFrom(address(token), alice, bob, firstTokenId);

        operator.tokenTransferFrom(address(token), alice, bob, secondTokenId);
    }

    function testAuthorizationModeRevertsWhenTransferringTokenIdsAuthorizationEnds(
        address alice,
        address bob,
        uint256 firstTokenId,
        uint256 secondTokenId
    ) external {
        _sanitizeAddress(alice);
        _sanitizeAddress(bob);

        vm.assume(alice != bob);
        vm.assume(firstTokenId != 0);
        vm.assume(secondTokenId != 0);
        vm.assume(firstTokenId != secondTokenId);

        ERC721CMock token = new ERC721CMock();
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection({
            collection: address(token),
            level: TRANSFER_SECURITY_LEVEL_RECOMMENDED,
            disableAuthorizationMode: false,
            disableWildcardOperators: true,
            enableAccountFreezingMode: false
        });

        uint120 listId = validator.createList("");
        validator.applyListToCollection(address(token), listId);
        address[] memory authorizers = new address[](1);
        authorizers[0] = address(this);
        validator.addAccountsToAuthorizers(listId, authorizers);

        OperatorMock operator = new OperatorMock();
        token.mint(alice, firstTokenId);
        token.mint(alice, secondTokenId);

        vm.prank(alice);
        token.setApprovalForAll(address(operator), true);
        /// @dev Enable the operator to transfer all tokens.
        validator.beforeAuthorizedTransfer(address(operator), address(token));
        operator.tokenTransferFrom(address(token), alice, bob, firstTokenId);

        validator.afterAuthorizedTransfer(address(token));

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector);
        operator.tokenTransferFrom(address(token), alice, bob, secondTokenId);
    }

    function testAuthorizationModeSucceedsWhenTransferringLegacyTokenIds(
        address alice,
        address bob,
        uint256 firstTokenId,
        uint256 secondTokenId
    ) external {
        _sanitizeAddress(alice);
        _sanitizeAddress(bob);

        vm.assume(alice != bob);
        vm.assume(firstTokenId != 0);
        vm.assume(secondTokenId != 0);
        vm.assume(firstTokenId != secondTokenId);

        LegacyTokenMock token = new LegacyTokenMock(validator);
        validator.setTransferSecurityLevelOfCollection({
            collection: address(token),
            level: TRANSFER_SECURITY_LEVEL_RECOMMENDED,
            disableAuthorizationMode: false,
            disableWildcardOperators: true,
            enableAccountFreezingMode: false
        });

        uint120 listId = validator.createList("");
        validator.applyListToCollection(address(token), listId);
        address[] memory authorizers = new address[](1);
        authorizers[0] = address(this);
        validator.addAccountsToAuthorizers(listId, authorizers);

        OperatorMock operator = new OperatorMock();

        /// @dev Enable the operator to transfer `firstTokenId`.
        validator.beforeAuthorizedTransfer(address(operator), address(token), firstTokenId);
        operator.tokenTransferFrom(address(token), alice, bob, firstTokenId);

        /// @dev Because this is a legacy token, additional transfers of tokenIds are allowed.
        operator.tokenTransferFrom(address(token), alice, bob, secondTokenId);
    }

    function testAuthorizationModeRevertsWhenTransferringLegacyTokenIdsAuthorizationEnds(
        address alice,
        address bob,
        uint256 firstTokenId,
        uint256 secondTokenId
    ) external {
        _sanitizeAddress(alice);
        _sanitizeAddress(bob);

        vm.assume(alice != bob);
        vm.assume(firstTokenId != 0);
        vm.assume(secondTokenId != 0);
        vm.assume(firstTokenId != secondTokenId);

        LegacyTokenMock token = new LegacyTokenMock(validator);
        validator.setTransferSecurityLevelOfCollection({
            collection: address(token),
            level: TRANSFER_SECURITY_LEVEL_RECOMMENDED,
            disableAuthorizationMode: false,
            disableWildcardOperators: true,
            enableAccountFreezingMode: false
        });

        uint120 listId = validator.createList("");
        validator.applyListToCollection(address(token), listId);
        address[] memory authorizers = new address[](1);
        authorizers[0] = address(this);
        validator.addAccountsToAuthorizers(listId, authorizers);

        OperatorMock operator = new OperatorMock();

        /// @dev Enable the operator to transfer `firstTokenId`.
        validator.beforeAuthorizedTransfer(address(operator), address(token), firstTokenId);
        operator.tokenTransferFrom(address(token), alice, bob, firstTokenId);

        validator.afterAuthorizedTransfer(address(token), firstTokenId);

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector);
        operator.tokenTransferFrom(address(token), alice, bob, secondTokenId);
    }

    // Lists

    function testCollectionSecuritySettingsApplied(
        FuzzedList memory fuzzedList,
        address collection,
        address operator,
        uint256 tokenId, 
        uint256 amount,
        uint8 transferSecurityLevel,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) public {
        address authorizer = fuzzedList.authorizerAddress;
        uint256 fromKey;
        (collection, operator, fromKey) = _sanitizeAccounts(collection, authorizer, operator, operator);
        transferSecurityLevel = uint8(bound(transferSecurityLevel, TRANSFER_SECURITY_LEVEL_RECOMMENDED, TRANSFER_SECURITY_LEVEL_NINE));
        _configureCollectionSecurity(
            collection, 
            fuzzedList, 
            transferSecurityLevel, 
            true, 
            authorizersCannotSetWildcardOperators, 
            enableAccountFreezingMode
        );

        assertTrue(validator.isAccountAuthorizerOfCollection(collection, authorizer));
        assertTrue(validator.isAccountWhitelistedByCollection(collection, fuzzedList.whitelistedAddress));
        assertTrue(validator.isAccountBlacklistedByCollection(collection, fuzzedList.blacklistedAddress));

        address[] memory accounts = validator.getAuthorizerAccountsByCollection(collection);
        assertEq(accounts.length, 1);
        assertEq(accounts[0], authorizer);

        accounts = validator.getWhitelistedAccountsByCollection(collection);
        assertEq(accounts.length, 2);
        assertEq(accounts[0], fuzzedList.whitelistedAddress);
        assertEq(accounts[1], fuzzedList.whitelistedToAddress);

        accounts = validator.getBlacklistedAccountsByCollection(collection);
        assertEq(accounts.length, 1);
        assertEq(accounts[0], fuzzedList.blacklistedAddress);

        bytes32 whitelistedCodeHash = keccak256(abi.encode(fuzzedList.whitelistedCode));
        assertTrue(validator.isCodeHashWhitelistedByCollection(collection, whitelistedCodeHash));
        bytes32[] memory codeHashes = validator.getWhitelistedCodeHashesByCollection(collection);
        assertEq(codeHashes.length, 1);
        assertEq(codeHashes[0], whitelistedCodeHash);

        bytes32 blacklistedCodeHash = keccak256(abi.encode(fuzzedList.blacklistedCode));
        assertTrue(validator.isCodeHashBlacklistedByCollection(collection, blacklistedCodeHash));
        codeHashes = validator.getBlacklistedCodeHashesByCollection(collection);
        assertEq(codeHashes.length, 1);
        assertEq(codeHashes[0], blacklistedCodeHash);
    }

    // Helpers

    function _pickAWhitelistingSecurityLevel(uint8 number) internal view returns (uint8) {
        number = uint8(bound(number, 0, 6));
        if (number == 0) {
            return TRANSFER_SECURITY_LEVEL_RECOMMENDED;
        } else if (number == 1) {
            return TRANSFER_SECURITY_LEVEL_THREE;
        } else if (number == 2) {
            return TRANSFER_SECURITY_LEVEL_FOUR;
        } else if (number == 3) {
            return TRANSFER_SECURITY_LEVEL_FIVE;
        } else if (number == 4) {
            return TRANSFER_SECURITY_LEVEL_SIX;
        } else if (number == 5) {
            return TRANSFER_SECURITY_LEVEL_SEVEN;
        } else if (number == 6) {
            return TRANSFER_SECURITY_LEVEL_EIGHT;
        }
    }

    function _sanitizeAccounts(
        address collection,
        address caller,
        address from,
        address to
    ) internal virtual returns(address sanitizedCollection, address sanitizedFrom, uint256 sanitizedFromKey) {
        _sanitizeAddress(collection);
        _sanitizeAddress(caller);
        _sanitizeAddress(from);
        _sanitizeAddress(to);

        sanitizedCollection = collection;
        sanitizedFrom = from;
    }

    function _freezeAccount(
        address collection,
        address account
    ) internal {
        address[] memory accountsToFreeze = new address[](1);
        accountsToFreeze[0] = account;

        vm.startPrank(collection);
        validator.freezeAccountsForCollection(collection, accountsToFreeze);
        vm.stopPrank();
    }

    function _etchCodeToCaller(
        address caller,
        bytes32 code
    ) internal virtual {
        bytes memory bytecode = abi.encode(code);
        vm.etch(caller, bytecode);
    }

    function _sanitizeCode(
        bytes32 whitelistedCode,
        bytes32 blacklistedCode,
        bool expectRevert
    ) internal virtual returns (bytes32 sanitizedWhitelistedCode, bytes32 sanitizedBlacklistedCode) {
        sanitizedWhitelistedCode = whitelistedCode;
        sanitizedBlacklistedCode = blacklistedCode;
    }

    function _configureCollectionSecurity(
        address collection,
        FuzzedList memory fuzzedList,
        uint8 transferSecurityLevel,
        bool disableAuthorizationMode,
        bool authorizersCannotSetWildcardOperators,
        bool enableAccountFreezingMode
    ) internal {
        vm.assume(fuzzedList.whitelistedCode != fuzzedList.blacklistedCode);
        vm.assume(fuzzedList.whitelistedAddress != fuzzedList.blacklistedAddress);
        vm.assume(fuzzedList.whitelistedToAddress != fuzzedList.blacklistedAddress);
        vm.assume(fuzzedList.whitelistedAddress != fuzzedList.whitelistedToAddress);
        vm.assume(fuzzedList.authorizerAddress != fuzzedList.whitelistedAddress);
        vm.assume(fuzzedList.authorizerAddress != fuzzedList.whitelistedToAddress);
        vm.assume(fuzzedList.authorizerAddress != fuzzedList.blacklistedAddress);

        vm.startPrank(collection);

        uint120 listId = validator.createList("test");

        validator.addAccountsToWhitelist(listId, _asSingletonArray(fuzzedList.whitelistedAddress));
        validator.addAccountsToWhitelist(listId, _asSingletonArray(fuzzedList.whitelistedToAddress));
        validator.addAccountsToBlacklist(listId, _asSingletonArray(fuzzedList.blacklistedAddress));
        validator.addAccountsToAuthorizers(listId, _asSingletonArray(fuzzedList.authorizerAddress));

        bytes memory whitelistedCode = abi.encode(fuzzedList.whitelistedCode);
        bytes memory blacklistedCode = abi.encode(fuzzedList.blacklistedCode);

        bytes32[] memory codeHashes = new bytes32[](1);
        codeHashes[0] = keccak256(whitelistedCode);
        validator.addCodeHashesToWhitelist(listId, codeHashes);
        codeHashes[0] = keccak256(blacklistedCode);
        validator.addCodeHashesToBlacklist(listId, codeHashes);

        validator.setTransferSecurityLevelOfCollection(
            collection, 
            transferSecurityLevel, 
            disableAuthorizationMode, 
            authorizersCannotSetWildcardOperators, 
            enableAccountFreezingMode);

        validator.applyListToCollection(collection, listId);

        vm.stopPrank();
    }

    function _configureCollectionTokenType(
        address collection,
        uint256 tokenType
    ) internal {
        vm.startPrank(collection);

        validator.setTokenTypeOfCollection(
            collection, 
            uint16(tokenType)
        );

        vm.stopPrank();
    }

    function _validateTransfersWithExpectedRevert(
        address collection,
        address caller,
        address origin,
        uint256 fromKey,
        address from, 
        address to,
        uint256 tokenId,
        uint256 amount,
        bytes4 expectedRevertSelector
    ) internal virtual {
        vm.startPrank(collection, origin);

        if (expectedRevertSelector != bytes4(0x00000000)) {
            vm.expectRevert(expectedRevertSelector);
        }
        validator.applyCollectionTransferPolicy(caller, from, to);

        if (expectedRevertSelector != bytes4(0x00000000)) {
            vm.expectRevert(expectedRevertSelector);
        }
        validator.validateTransfer(caller, from, to);

        if (expectedRevertSelector != bytes4(0x00000000)) {
            vm.expectRevert(expectedRevertSelector);
        }
        validator.validateTransfer(caller, from, to, tokenId);

        if (expectedRevertSelector != bytes4(0x00000000)) {
            vm.expectRevert(expectedRevertSelector);
        }
        validator.validateTransfer(caller, from, to, tokenId, amount);

        vm.stopPrank();
    }

    function _beforeAuthorizedTransferCallsWithExpectedRevert(
        address authorizer,
        address origin,
        address operator,
        address collection,
        uint256 tokenId,
        uint256 amount,
        bytes4 expectedRevertSelector
    ) internal virtual {
        vm.startPrank(authorizer, origin);

        if (expectedRevertSelector != bytes4(0x00000000)) {
            vm.expectRevert(expectedRevertSelector);
        }
        validator.beforeAuthorizedTransfer(operator, collection, tokenId);

        if (expectedRevertSelector != bytes4(0x00000000)) {
            vm.expectRevert(expectedRevertSelector);
        }
        validator.beforeAuthorizedTransfer(operator, collection);

        if (expectedRevertSelector != bytes4(0x00000000)) {
            vm.expectRevert(expectedRevertSelector);
        }
        validator.beforeAuthorizedTransfer(collection, tokenId);

        if (expectedRevertSelector != bytes4(0x00000000)) {
            vm.expectRevert(expectedRevertSelector);
        }
        validator.beforeAuthorizedTransferWithAmount(collection, tokenId, amount);

        vm.stopPrank();
    }

    function _afterAuthorizedTransferCallsWithExpectedRevert(
        address authorizer,
        address origin,
        address operator,
        address collection,
        uint256 tokenId,
        bytes4 expectedRevertSelector
    ) internal virtual {
        vm.startPrank(authorizer, origin);

        if (expectedRevertSelector != bytes4(0x00000000)) {
            vm.expectRevert(expectedRevertSelector);
        }
        validator.afterAuthorizedTransfer(collection, tokenId);

        if (expectedRevertSelector != bytes4(0x00000000)) {
            vm.expectRevert(expectedRevertSelector);
        }
        validator.afterAuthorizedTransfer(collection);

        if (expectedRevertSelector != bytes4(0x00000000)) {
            vm.expectRevert(expectedRevertSelector);
        }
        validator.afterAuthorizedTransferWithAmount(collection, tokenId);

        vm.stopPrank();
    }

    function _asSingletonArray(address account) private pure returns (address[] memory array) {
        array = new address[](1);
        array[0] = account;
    }
}

contract OperatorMock {
    function tokenTransferFrom(address token, address from, address to, uint256 tokenId) external {
        IERC721(token).transferFrom(from, to, tokenId);
    }
}

contract LegacyTokenMock {
    CreatorTokenTransferValidator validator;
    address public owner;
    constructor(CreatorTokenTransferValidator _validator) {
        validator = _validator;
        owner = msg.sender;
    }

    function transferFrom(address from, address to, uint256) external {
        validator.applyCollectionTransferPolicy(msg.sender, from, to);
    }
}