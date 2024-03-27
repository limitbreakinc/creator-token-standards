// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/console.sol";
import "./mocks/ClonerMock.sol";
import "./mocks/ContractMock.sol";
import "./mocks/ERC721CMock.sol";
import "./interfaces/ITestCreatorToken.sol";
import "src/utils/TransferPolicy.sol";
import "src/utils/CreatorTokenTransferValidator.sol";
import "src/Constants.sol";
import "./utils/Events.sol";
import "./utils/Helpers.sol";

contract TransferValidatorTest is Events, Helpers {
    //using EnumerableSet for EnumerableSet.AddressSet;
    //using EnumerableSet for EnumerableSet.Bytes32Set;

    CreatorTokenTransferValidator public validator;

    address whitelistedOperator;

    function setUp() public virtual override {
        super.setUp();

        validator = new CreatorTokenTransferValidator(address(this), "", "");

        whitelistedOperator = vm.addr(2);

        // TODO: vm.prank(validatorDeployer);
        // TODO: validator.addOperatorToWhitelist(0, whitelistedOperator);
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
        validator.addAccountToWhitelist(sourceListId, whitelistedAccount);
        validator.addAccountToWhitelist(sourceListId, address(uint160(uint256(keccak256(abi.encode(whitelistedAccount))))));
        validator.addAccountToBlacklist(sourceListId, blacklistedAccount);
        validator.addAccountToBlacklist(sourceListId, address(uint160(uint256(keccak256(abi.encode(blacklistedAccount))))));
        validator.addAccountToAuthorizers(sourceListId, authorizerAccount);
        validator.addAccountToAuthorizers(sourceListId, address(uint160(uint256(keccak256(abi.encode(authorizerAccount))))));
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
        bool enableAuthorizationMode,
        bool enableAccountFreezingMode
    ) public {
        _sanitizeAddress(collection);

        level = uint8(bound(level, TRANSFER_SECURITY_LEVEL_RECOMMENDED, TRANSFER_SECURITY_LEVEL_NINE));

        vm.expectEmit(true, true, true, true);
        emit SetTransferSecurityLevel(collection, level);

        vm.expectEmit(true, true, true, true);
        emit SetAuthorizationModeEnabled(collection, enableAuthorizationMode);

        vm.expectEmit(true, true, true, true);
        emit SetAccountFreezingModeEnabled(collection, enableAccountFreezingMode);

        vm.prank(collection);
        validator.setTransferSecurityLevelOfCollection(
            collection, 
            level, 
            enableAuthorizationMode, 
            enableAccountFreezingMode);

        CollectionSecurityPolicyV3 memory policy = validator.getCollectionSecurityPolicy(collection);

        assertEq(policy.transferSecurityLevel, level);
        assertEq(policy.enableAuthorizationMode, enableAuthorizationMode);
        assertEq(policy.enableAccountFreezingMode, enableAccountFreezingMode);
    }

    function testRevertsWhenSecurityLevelOutOfRangeForSetTransferSecurityLevelOfCollection(
        address collection,
        uint8 level,
        bool enableAuthorizationMode,
        bool enableAccountFreezingMode
    ) public {
        _sanitizeAddress(collection);

        level = uint8(bound(level, TRANSFER_SECURITY_LEVEL_NINE + 1, type(uint8).max));

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__InvalidTransferSecurityLevel.selector);
        vm.prank(collection);
        validator.setTransferSecurityLevelOfCollection(collection, level, enableAuthorizationMode, enableAccountFreezingMode);
    }

    function testRevertsWhenUnauthorizedUserCallsSetTransferSecurityLevelOfCollection(
        address collection,
        address unauthorizedUser,
        uint8 level,
        bool enableAuthorizationMode,
        bool enableAccountFreezingMode
    ) public {
        _sanitizeAddress(collection);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(collection != unauthorizedUser);

        level = uint8(bound(level, TRANSFER_SECURITY_LEVEL_RECOMMENDED, TRANSFER_SECURITY_LEVEL_NINE));

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustHaveElevatedPermissionsForSpecifiedNFT.selector);
        vm.prank(unauthorizedUser);
        validator.setTransferSecurityLevelOfCollection(collection, level, enableAuthorizationMode, enableAccountFreezingMode);
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


    /*

    function testAddToOperatorWhitelist(address originalListOwner, address operator) public {
        vm.assume(originalListOwner != address(0));
        vm.assume(operator != address(0));

        vm.startPrank(originalListOwner);
        uint120 listId = validator.createOperatorWhitelist("test");

        vm.expectEmit(true, true, true, false);
        emit AddedAccountToList(ListTypes.Whitelist, listId, operator);

        validator.addOperatorToWhitelist(listId, operator);
        vm.stopPrank();

        assertTrue(validator.isOperatorWhitelisted(listId, operator));
    }

    function testWhitelistedOperatorsCanBeQueriedOnCreatorTokensDeprecated(
        address creator,
        address operator1,
        address operator2,
        address operator3
    ) public {
        vm.assume(creator != address(0));
        vm.assume(operator1 != address(0));
        vm.assume(operator2 != address(0));
        vm.assume(operator3 != address(0));
        vm.assume(operator1 != operator2);
        vm.assume(operator1 != operator3);
        vm.assume(operator2 != operator3);

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.startPrank(creator);
        uint120 listId = validator.createOperatorWhitelist("");
        token.setTransferValidator(address(validator));
        validator.setOperatorWhitelistOfCollection(address(token), listId);
        validator.addOperatorToWhitelist(listId, operator1);
        validator.addOperatorToWhitelist(listId, operator2);
        validator.addOperatorToWhitelist(listId, operator3);
        vm.stopPrank();

        vm.expectRevert(CreatorTokenBase.CreatorTokenBase__FunctionDeprecatedUseTransferValidatorInstead.selector);
        address[] memory allowedAddresses = token.getWhitelistedOperators();
    }

    function testPermittedContractReceiversCanBeQueriedOnCreatorTokens(
        address creator,
        address receiver1,
        address receiver2,
        address receiver3
    ) public {
        vm.assume(creator != address(0));
        vm.assume(receiver1 != address(0));
        vm.assume(receiver2 != address(0));
        vm.assume(receiver3 != address(0));
        vm.assume(receiver1 != receiver2);
        vm.assume(receiver1 != receiver3);
        vm.assume(receiver2 != receiver3);

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        address[] memory receivers = new address[](3);
        receivers[0] = receiver1;
        receivers[1] = receiver2;
        receivers[2] = receiver3;

        vm.startPrank(creator);
        uint120 listId = validator.createList("");
        token.setTransferValidator(address(validator));
        validator.applyListToCollection(address(token), listId);
        validator.addAccountsToWhitelist(listId, receivers);
        vm.stopPrank();

        assertTrue(validator.isContractReceiverPermitted(listId, receiver1));
        assertTrue(validator.isContractReceiverPermitted(listId, receiver2));
        assertTrue(validator.isContractReceiverPermitted(listId, receiver3));
    }

    function testIsTransferAllowedReturnsTrueWhenTransferValidatorIsSetToZero(
        address creator,
        address caller,
        address from,
        address to
    ) public {
        vm.assume(caller != whitelistedOperator);
        vm.assume(from != whitelistedOperator);
        vm.assume(to != whitelistedOperator);
        vm.assume(creator != address(0));
        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);
        
        vm.prank(creator);
        token.setTransferValidator(address(0));

        assertTrue(token.isTransferAllowed(caller, from, to));
    }

    function testRevertsWhenNonOwnerAddsOperatorToWhitelist(
        address originalListOwner,
        address unauthorizedUser,
        address operator
    ) public {
        vm.assume(originalListOwner != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(operator != address(0));
        vm.assume(originalListOwner != unauthorizedUser);

        vm.prank(originalListOwner);
        uint120 listId = validator.createOperatorWhitelist("test");
        assertEq(validator.listOwners(listId), originalListOwner);

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addOperatorToWhitelist(listId, operator);
    }

    function testWhenOperatorAddedToWhitelistAgainNoDuplicatesAreAdded(address originalListOwner, address operator) public {
        vm.assume(originalListOwner != address(0));
        vm.assume(operator != address(0));

        vm.startPrank(originalListOwner);
        uint120 listId = validator.createOperatorWhitelist("test");
        validator.addOperatorToWhitelist(listId, operator);

        validator.addOperatorToWhitelist(listId, operator);
        
        address[] memory whitelistedAddresses = validator.getWhitelistedAccounts(listId);
        assertEq(whitelistedAddresses.length, 1);
        assertTrue(whitelistedAddresses[0] == operator);
    }

    function testRemoveOperatorFromWhitelist(address originalListOwner, address operator) public {
        vm.assume(originalListOwner != address(0));
        vm.assume(operator != address(0));

        vm.startPrank(originalListOwner);
        uint120 listId = validator.createOperatorWhitelist("test");
        validator.addOperatorToWhitelist(listId, operator);
        assertTrue(validator.isOperatorWhitelisted(listId, operator));

        vm.expectEmit(true, true, true, false);
        emit RemovedAccountFromList(ListTypes.Whitelist, listId, operator);

        validator.removeOperatorFromWhitelist(listId, operator);

        assertFalse(validator.isOperatorWhitelisted(listId, operator));
        vm.stopPrank();
    }

    function testRevertsWhenUnwhitelistedOperatorRemovedFromWhitelist(address originalListOwner, address operator)
        public
    {
        vm.assume(originalListOwner != address(0));
        vm.assume(operator != address(0));

        vm.startPrank(originalListOwner);
        uint120 listId = validator.createOperatorWhitelist("test");
        assertFalse(validator.isOperatorWhitelisted(listId, operator));

        validator.removeOperatorFromWhitelist(listId, operator);
        vm.stopPrank();

        assertFalse(validator.isAccountWhitelisted(listId, operator));
    }

    function testAddManyOperatorsToWhitelist(address originalListOwner) public {
        vm.assume(originalListOwner != address(0));

        vm.startPrank(originalListOwner);
        uint120 listId = validator.createOperatorWhitelist("test");

        for (uint256 i = 1; i <= 10; i++) {
            validator.addOperatorToWhitelist(listId, vm.addr(i));
        }
        vm.stopPrank();

        for (uint256 i = 1; i <= 10; i++) {
            assertTrue(validator.isOperatorWhitelisted(listId, vm.addr(i)));
        }

        address[] memory whitelistedOperators = validator.getWhitelistedOperators(listId);
        assertEq(whitelistedOperators.length, 10);

        for (uint256 i = 0; i < whitelistedOperators.length; i++) {
            assertEq(vm.addr(i + 1), whitelistedOperators[i]);
        }
    }

    function testSupportedInterfaces() public {
        assertEq(validator.supportsInterface(type(ITransferValidator).interfaceId), true);
        // TODO: assertEq(validator.supportsInterface(type(ITransferSecurityRegistry).interfaceId), true);
        // TODO: assertEq(validator.supportsInterface(type(ICreatorTokenTransferValidator).interfaceId), true);
        assertEq(validator.supportsInterface(type(IEOARegistry).interfaceId), true);
        assertEq(validator.supportsInterface(type(IERC165).interfaceId), true);
    }

    function testPolicyLevelOnePermitsAllTransfers(address creator, address caller, address from, address to) public {
        vm.assume(creator != address(0));
        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);
        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), TransferSecurityLevels.One);
        vm.stopPrank();
        assertTrue(token.isTransferAllowed(caller, from, to));
    }

    function testWhitelistPoliciesWithOTCEnabledBlockTransfersWhenCallerNotWhitelistedOrOwner(
        address creator,
        address caller,
        address from,
        uint160 toKey
    ) public {
        _sanitizeAddress(caller);
        _sanitizeAddress(from);
        address to = _verifyEOA(toKey);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Recommended, creator, caller, from, to);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Three, creator, caller, from, to);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Five, creator, caller, from, to);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Six, creator, caller, from, to);
    }

    function testWhitelistPoliciesWithOTCEnabledAllowTransfersWhenCalledByOwner(
        address creator,
        address tokenOwner,
        uint160 toKey
    ) public {
        address to = _verifyEOA(toKey);
        _testPolicyAllowsTransfersWhenCalledByOwner(TransferSecurityLevels.Recommended, creator, tokenOwner, to);
        _testPolicyAllowsTransfersWhenCalledByOwner(TransferSecurityLevels.Three, creator, tokenOwner, to);
        _testPolicyAllowsTransfersWhenCalledByOwner(TransferSecurityLevels.Five, creator, tokenOwner, to);
        _testPolicyAllowsTransfersWhenCalledByOwner(TransferSecurityLevels.Six, creator, tokenOwner, to);
    }

    function testWhitelistPoliciesWithOTCDisabledBlockTransfersWhenCallerNotWhitelistedOrOwner(
        address creator,
        address caller,
        address from,
        uint160 toKey
    ) public {
        address to = _verifyEOA(toKey);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Four, creator, caller, from, to);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Seven, creator, caller, from, to);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Eight, creator, caller, from, to);
    }

    function testWhitelistPoliciesWithOTCDisabledBlockTransfersWhenCalledByOwner(
        address creator,
        address tokenOwner,
        uint160 toKey
    ) public {
        address to = _verifyEOA(toKey);
        _testPolicyBlocksTransfersWhenCalledByOwner(TransferSecurityLevels.Four, creator, tokenOwner, to);
        _testPolicyBlocksTransfersWhenCalledByOwner(TransferSecurityLevels.Seven, creator, tokenOwner, to);
        _testPolicyBlocksTransfersWhenCalledByOwner(TransferSecurityLevels.Eight, creator, tokenOwner, to);
    }

    function testNoCodePoliciesBlockTransferWhenDestinationIsAContract(address creator, address caller, address from)
        public
    {
        _sanitizeAddress(caller);
        _sanitizeAddress(from);
        _testPolicyBlocksTransfersToContractReceivers(TransferSecurityLevels.Five, creator, caller, from);
        _testPolicyBlocksTransfersToContractReceivers(TransferSecurityLevels.Seven, creator, caller, from);
    }

    function testNoCodePoliciesAllowTransferToPermittedContractDestinations(
        address creator,
        address caller,
        address from
    ) public {
        _testPolicyAllowsTransfersToPermittedContractReceivers(TransferSecurityLevels.Four, creator, caller, from);
        _testPolicyAllowsTransfersToPermittedContractReceivers(TransferSecurityLevels.Six, creator, caller, from);
    }

    function testEOAPoliciesBlockTransferWhenDestinationHasNotVerifiedSignature(
        address creator,
        address caller,
        address from,
        address to
    ) public {
        _testPolicyBlocksTransfersToWalletsThatHaveNotVerifiedEOASignature(
            TransferSecurityLevels.Six, creator, caller, from, to
        );
        _testPolicyBlocksTransfersToWalletsThatHaveNotVerifiedEOASignature(
            TransferSecurityLevels.Eight, creator, caller, from, to
        );
    }

    function testEOAPoliciesAllowTransferWhenDestinationHasVerifiedSignature(
        address creator,
        address caller,
        address from,
        uint160 toKey
    ) public {
        address to = _verifyEOA(toKey);
        _testPolicyAllowsTransfersToWalletsThatHaveVerifiedEOASignature(
            TransferSecurityLevels.Five, creator, caller, from, to
        );
        _testPolicyAllowsTransfersToWalletsThatHaveVerifiedEOASignature(
            TransferSecurityLevels.Seven, creator, caller, from, to
        );
    }

    function testEOAPoliciesAllowTransferToPermittedContractDestinations(address creator, address caller, address from)
        public
    {
        _sanitizeAddress(caller);
        _sanitizeAddress(creator);
        _sanitizeAddress(from);
        _testPolicyAllowsTransfersToPermittedContractReceivers(TransferSecurityLevels.Six, creator, caller, from);
        _testPolicyAllowsTransfersToPermittedContractReceivers(TransferSecurityLevels.Eight, creator, caller, from);
    }

    function _testPolicyAllowsAllTransfersWhenOperatorWhitelistIsEmpty(
        TransferSecurityLevels level,
        address creator,
        address caller,
        address from,
        address to
    ) private {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.assume(caller != address(token));
        vm.assume(caller != whitelistedOperator);
        vm.assume(caller != address(0));
        vm.assume(from != address(0));
        vm.assume(from != caller);
        vm.assume(from != address(token));
        vm.assume(to != address(0));
        vm.assume(to != address(token));

        vm.startPrank(creator);

        uint120 listId = validator.createList("");

        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.setOperatorWhitelistOfCollection(address(token), listId);
        vm.stopPrank();

        assertTrue(token.isTransferAllowed(caller, from, to));

        _mintToken(address(token), from, 1);

        vm.prank(from);
        token.setApprovalForAll(caller, true);

        vm.prank(caller);
        token.transferFrom(from, to, 1);
        assertEq(token.ownerOf(1), to);
    }

    function _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(
        TransferSecurityLevels level,
        address creator,
        address caller,
        address from,
        address to
    ) private {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.assume(caller != address(token));
        vm.assume(caller != whitelistedOperator);
        vm.assume(caller != address(0));
        vm.assume(from != address(0));
        vm.assume(from != caller);
        vm.assume(from != address(token));
        vm.assume(to != address(0));
        vm.assume(to != address(token));

        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.setOperatorWhitelistOfCollection(address(token), 0);
        vm.stopPrank();

        assertFalse(token.isTransferAllowed(caller, from, to));

        _mintToken(address(token), from, 1);

        vm.prank(from);
        token.setApprovalForAll(caller, true);

        vm.prank(caller);
        vm.expectRevert(
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector
        );
        token.transferFrom(from, to, 1);
    }

    function _testPolicyAllowsTransfersWhenCalledByOwner(
        TransferSecurityLevels level,
        address creator,
        address tokenOwner,
        address to
    ) private {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.assume(tokenOwner != address(token));
        vm.assume(tokenOwner != whitelistedOperator);
        vm.assume(tokenOwner != address(0));
        vm.assume(to != address(0));
        vm.assume(to != address(token));

        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.setOperatorWhitelistOfCollection(address(token), 0);
        vm.stopPrank();

        assertTrue(token.isTransferAllowed(tokenOwner, tokenOwner, to));

        _mintToken(address(token), tokenOwner, 1);

        vm.prank(tokenOwner);
        token.transferFrom(tokenOwner, to, 1);

        assertEq(token.ownerOf(1), to);
    }

    function _testPolicyBlocksTransfersWhenCalledByOwner(
        TransferSecurityLevels level,
        address creator,
        address tokenOwner,
        address to
    ) private {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.assume(tokenOwner != address(token));
        vm.assume(tokenOwner != whitelistedOperator);
        vm.assume(tokenOwner != address(0));
        vm.assume(to != address(0));
        vm.assume(to != address(token));

        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.setOperatorWhitelistOfCollection(address(token), 0);
        vm.stopPrank();

        assertFalse(token.isTransferAllowed(tokenOwner, tokenOwner, to));

        _mintToken(address(token), tokenOwner, 1);

        vm.prank(tokenOwner);
        vm.expectRevert(
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector
        );
        token.transferFrom(tokenOwner, to, 1);
    }

    function _testPolicyBlocksTransfersToContractReceivers(
        TransferSecurityLevels level,
        address creator,
        address caller,
        address from
    ) private {
        vm.assume(creator != address(0));

        if (!validator.isOperatorWhitelisted(0, caller)) {
            vm.prank(validatorDeployer);
            validator.addOperatorToWhitelist(0, caller);
        }

        vm.prank(creator);
        address to = address(new ContractMock());

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.assume(caller != address(token));
        vm.assume(from != address(0));
        vm.assume(from != address(token));

        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.setOperatorWhitelistOfCollection(address(token), 0);
        vm.stopPrank();

        assertFalse(token.isTransferAllowed(caller, from, to));

        _mintToken(address(token), from, 1);

        if (caller != from) {
            vm.prank(from);
            token.setApprovalForAll(caller, true);
        }

        vm.prank(caller);
        vm.expectRevert(
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__ReceiverMustNotHaveDeployedCode.selector
        );
        token.transferFrom(from, to, 1);
    }

    function _testPolicyBlocksTransfersToWalletsThatHaveNotVerifiedEOASignature(
        TransferSecurityLevels level,
        address creator,
        address caller,
        address from,
        address to
    ) private {
        vm.assume(creator != address(0));

        if (!validator.isOperatorWhitelisted(0, caller)) {
            vm.prank(validatorDeployer);
            validator.addOperatorToWhitelist(0, caller);
        }

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.assume(caller != address(token));
        vm.assume(caller != address(0));
        vm.assume(from != address(0));
        vm.assume(from != address(token));
        vm.assume(to != address(0));
        vm.assume(to != address(token));
        vm.assume(to != whitelistedOperator);

        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.setOperatorWhitelistOfCollection(address(token), 0);
        vm.stopPrank();

        assertFalse(token.isTransferAllowed(caller, from, to));

        _mintToken(address(token), from, 1);

        if (caller != from) {
            vm.prank(from);
            token.setApprovalForAll(caller, true);
        }

        vm.prank(caller);
        vm.expectRevert(
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__ReceiverProofOfEOASignatureUnverified.selector
        );
        token.transferFrom(from, to, 1);
    }

    function _testPolicyAllowsTransfersToWalletsThatHaveVerifiedEOASignature(
        TransferSecurityLevels level,
        address creator,
        address caller,
        address from,
        address to
    ) private {
        vm.assume(creator != address(0));

        if (!validator.isOperatorWhitelisted(0, caller)) {
            vm.prank(validatorDeployer);
            validator.addOperatorToWhitelist(0, caller);
        }

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.assume(caller != address(token));
        vm.assume(caller != address(0));
        vm.assume(from != address(0));
        vm.assume(from != address(token));
        vm.assume(to != address(0));
        vm.assume(to != address(token));

        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.setOperatorWhitelistOfCollection(address(token), 0);
        vm.stopPrank();

        assertTrue(token.isTransferAllowed(caller, from, to));

        _mintToken(address(token), from, 1);

        if (caller != from) {
            vm.prank(from);
            token.setApprovalForAll(caller, true);
        }

        vm.prank(caller);
        token.transferFrom(from, to, 1);
        assertEq(token.ownerOf(1), to);
    }

    function _testPolicyAllowsTransfersToPermittedContractReceivers(
        TransferSecurityLevels level,
        address creator,
        address caller,
        address from
    ) private {
        vm.assume(creator != address(0));

        vm.prank(creator);
        address to = address(new ContractMock());

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.assume(caller != address(token));
        vm.assume(from != address(0));
        vm.assume(from != address(token));

        vm.startPrank(creator);

        uint120 listId = validator.createList("");
        address[] memory permittedContractReceivers = new address[](1);
        permittedContractReceivers[0] = to;
        validator.addAccountsToWhitelist(listId, permittedContractReceivers);

        if (!validator.isAccountWhitelisted(listId, caller)) {
            validator.addOperatorToWhitelist(listId, caller);
        }

        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.applyListToCollection(address(token), listId);
        vm.stopPrank();

        assertTrue(token.isTransferAllowed(caller, from, to));

        _mintToken(address(token), from, 1);

        if (caller != from) {
            vm.prank(from);
            token.setApprovalForAll(caller, true);
        }

        vm.prank(caller);
        token.transferFrom(from, to, 1);
        assertEq(token.ownerOf(1), to);
    }

    function testCreateList(address listOwner, string memory name) public {
        _sanitizeAddress(listOwner);
        vm.assume(bytes(name).length < 200);

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

    function testCreateListCopy(address listOwnerSource, address listOwnerTarget, string memory nameSource, string memory nameTarget) public {
        _sanitizeAddress(listOwnerSource);
        _sanitizeAddress(listOwnerTarget);
        vm.assume(bytes(nameSource).length < 200);
        vm.assume(bytes(nameTarget).length < 200);

        address[] memory blAccounts = new address[](5);
        address[] memory wlAccounts = new address[](5);
        bytes32[] memory blCodehashes = new bytes32[](1);
        bytes32[] memory wlCodehashes = new bytes32[](1);

        for (uint256 a = 1; a <= 5; ++a) {
            blAccounts[a - 1] = vm.addr(a);
        }

        for (uint256 a = 6; a <= 10; ++a) {
            wlAccounts[a - 6] = vm.addr(a);
        }

        blCodehashes[0] = address(new ContractMock()).codehash;
        wlCodehashes[0] = address(new ClonerMock()).codehash;

        uint120 firstListId = 1;
        for (uint120 i = 0; i < 5; ++i) {
            uint120 expectedId = firstListId + i;

            vm.expectEmit(true, true, true, false);
            emit CreatedList(expectedId, nameSource);

            vm.expectEmit(true, true, true, false);
            emit ReassignedListOwnership(expectedId, listOwnerSource);

            vm.prank(listOwnerSource);
            uint120 actualId = validator.createList(nameSource);
            assertEq(actualId, expectedId);
            assertEq(validator.listOwners(actualId), listOwnerSource);

            vm.startPrank(listOwnerSource);
            validator.addAccountsToBlacklist(actualId, blAccounts);
            validator.addAccountsToWhitelist(actualId, wlAccounts);
            validator.addCodeHashesToBlacklist(actualId, blCodehashes);
            validator.addCodeHashesToWhitelist(actualId, wlCodehashes);
            vm.stopPrank();
        }

        for (uint120 i = 0; i < 5; ++i) {
            uint120 sourceId = firstListId + i;
            uint120 expectedId = firstListId + 5 + i;

            vm.expectEmit(true, true, true, false);
            emit CreatedList(expectedId, nameTarget);

            vm.expectEmit(true, true, true, false);
            emit ReassignedListOwnership(expectedId, listOwnerTarget);

            vm.prank(listOwnerTarget);
            uint120 actualId = validator.createListCopy(nameSource, sourceId);
            assertEq(actualId, expectedId);
            assertEq(validator.listOwners(actualId), listOwnerTarget);

            address[] memory blAccountsTarget = validator.getBlacklistedAccounts(actualId);
            address[] memory wlAccountsTarget = validator.getWhitelistedAccounts(actualId);
            bytes32[] memory blCodehashesTarget = validator.getBlacklistedCodeHashes(actualId);
            bytes32[] memory wlCodehashesTarget = validator.getWhitelistedCodeHashes(actualId);

            assertEq(blAccountsTarget.length, blAccounts.length);
            assertEq(wlAccountsTarget.length, wlAccounts.length);
            assertEq(blCodehashesTarget.length, blCodehashes.length);
            assertEq(wlCodehashesTarget.length, wlCodehashes.length);

            for (uint256 index = 0; index < blAccounts.length; ++index) {
                assertEq(blAccountsTarget[index], blAccounts[index]);
            }

            for (uint256 index = 0; index < wlAccounts.length; ++index) {
                assertEq(wlAccountsTarget[index], wlAccounts[index]);
            }

            for (uint256 index = 0; index < blCodehashes.length; ++index) {
                assertEq(blCodehashesTarget[index], blCodehashes[index]);
            }

            for (uint256 index = 0; index < wlCodehashes.length; ++index) {
                assertEq(wlCodehashesTarget[index], wlCodehashes[index]);
            }
        }
    }

    function testListCopyRevertsWhenCopyingANonExistentList(uint120 sourceListId) public {
        vm.assume(sourceListId > validator.lastListId());
        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__ListDoesNotExist.selector);
        validator.createListCopy("", sourceListId);
    }

    function testReassignOwnershipOfList(address originalListOwner, address newListOwner) public {
        vm.assume(originalListOwner != address(0));
        vm.assume(newListOwner != address(0));
        vm.assume(originalListOwner != newListOwner);

        vm.prank(originalListOwner);
        uint120 listId = validator.createList("test");
        assertEq(validator.listOwners(listId), originalListOwner);

        vm.expectEmit(true, true, true, false);
        emit ReassignedListOwnership(listId, newListOwner);

        vm.prank(originalListOwner);
        validator.reassignOwnershipOfList(listId, newListOwner);
        assertEq(validator.listOwners(listId), newListOwner);
    }

    function testRevertsWhenReassigningOwnershipOfListToZero(address originalListOwner) public {
        vm.assume(originalListOwner != address(0));

        vm.prank(originalListOwner);
        uint120 listId = validator.createList("test");
        assertEq(validator.listOwners(listId), originalListOwner);

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__ListOwnershipCannotBeTransferredToZeroAddress.selector);
        validator.reassignOwnershipOfList(listId, address(0));
    }

    function testRenounceOwnershipOfList(address originalListOwner) public {
        vm.assume(originalListOwner != address(0));

        vm.prank(originalListOwner);
        uint120 listId = validator.createOperatorWhitelist("test");
        assertEq(validator.listOwners(listId), originalListOwner);

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
        vm.assume(originalListOwner != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(originalListOwner != unauthorizedUser);

        vm.prank(originalListOwner);
        uint120 listId = validator.createList("test");
        assertEq(validator.listOwners(listId), originalListOwner);

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.renounceOwnershipOfList(listId);
    }

    function testRevertsWhenNonOwnerAddsAccountToBlacklist(address listOwner, address unauthorizedUser, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        _sanitizeAddress(account);
        vm.assume(listOwner != unauthorizedUser);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](1);
        accounts[0] = account;

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addAccountsToBlacklist(listId, accounts);
    }

    function testRevertsWhenBlacklistingEmptyAccountArray(address listOwner) public {
        _sanitizeAddress(listOwner);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](0);

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__ArrayLengthCannotBeZero.selector);
        vm.prank(listOwner);
        validator.addAccountsToBlacklist(listId, accounts);
    }

    function testRevertsWhenBlacklistingZeroAddress(address listOwner, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](2);
        accounts[0] = account;
        accounts[1] = address(0);

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__ZeroAddressNotAllowed.selector);
        vm.prank(listOwner);
        validator.addAccountsToBlacklist(listId, accounts);
    }

    function testNoDuplicateAddressesInBlacklist(address listOwner, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](3);
        accounts[0] = account;
        accounts[1] = account;
        accounts[2] = account;

        vm.startPrank(listOwner);
        validator.addAccountsToBlacklist(listId, accounts);
        validator.addAccountsToBlacklist(listId, accounts);
        vm.stopPrank();

        assertEq(validator.getBlacklistedAccounts(listId).length, 1);
        assertEq(validator.getBlacklistedAccounts(listId)[0], account);
        assertTrue(validator.isAccountBlacklisted(listId, account));

        ITestCreatorToken token = _deployNewToken(address(this));
        validator.applyListToCollection(address(token), listId);

        assertEq(validator.getBlacklistedAccountsByCollection(address(token)).length, 1);
        assertEq(validator.getBlacklistedAccountsByCollection(address(token))[0], account);
        assertTrue(validator.isAccountBlacklistedByCollection(address(token), account));

        //assertEq(token.getBlacklistedAccounts().length, 1);
        //assertEq(token.getBlacklistedAccounts()[0], account);
        //assertTrue(token.isAccountBlacklisted(account));
    }

    function testAddAccountsToBlacklist(address listOwner, address account1, address account2, address account3) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account1);
        _sanitizeAddress(account2);
        _sanitizeAddress(account3);
        vm.assume(account1 != account2);
        vm.assume(account1 != account3);
        vm.assume(account2 != account3);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](2);
        accounts[0] = account1;
        accounts[1] = account2;

        address[] memory accountsBatch2 = new address[](1);
        accountsBatch2[0] = account3;

        vm.startPrank(listOwner);
        validator.addAccountsToBlacklist(listId, accounts);
        validator.addAccountsToBlacklist(listId, accountsBatch2);
        vm.stopPrank();

        assertEq(validator.getBlacklistedAccounts(listId).length, 3);
        assertTrue(validator.isAccountBlacklisted(listId, account1));
        assertTrue(validator.isAccountBlacklisted(listId, account2));
        assertTrue(validator.isAccountBlacklisted(listId, account3));

        ITestCreatorToken token = _deployNewToken(address(this));
        validator.applyListToCollection(address(token), listId);

        assertEq(validator.getBlacklistedAccountsByCollection(address(token)).length, 3);
        assertTrue(validator.isAccountBlacklistedByCollection(address(token), account1));
        assertTrue(validator.isAccountBlacklistedByCollection(address(token), account2));
        assertTrue(validator.isAccountBlacklistedByCollection(address(token), account3));

        //assertEq(token.getBlacklistedAccounts().length, 3);
        //assertTrue(token.isAccountBlacklisted(account1));
        //assertTrue(token.isAccountBlacklisted(account2));
        //assertTrue(token.isAccountBlacklisted(account3));
    }

    function testRevertsWhenNonOwnerAddsAccountToWhitelist(address listOwner, address unauthorizedUser, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        _sanitizeAddress(account);
        vm.assume(listOwner != unauthorizedUser);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](1);
        accounts[0] = account;

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addAccountsToWhitelist(listId, accounts);
    }

    function testRevertsWhenWhitelistingEmptyAccountArray(address listOwner) public {
        _sanitizeAddress(listOwner);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](0);

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__ArrayLengthCannotBeZero.selector);
        vm.prank(listOwner);
        validator.addAccountsToWhitelist(listId, accounts);
    }

    function testRevertsWhenWhitelistingZeroAddress(address listOwner, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](2);
        accounts[0] = account;
        accounts[1] = address(0);

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__ZeroAddressNotAllowed.selector);
        vm.prank(listOwner);
        validator.addAccountsToWhitelist(listId, accounts);
    }

    function testNoDuplicateAddressesInWhitelist(address listOwner, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](3);
        accounts[0] = account;
        accounts[1] = account;
        accounts[2] = account;

        vm.startPrank(listOwner);
        validator.addAccountsToWhitelist(listId, accounts);
        validator.addAccountsToWhitelist(listId, accounts);
        vm.stopPrank();

        assertEq(validator.getWhitelistedAccounts(listId).length, 1);
        assertEq(validator.getWhitelistedAccounts(listId)[0], account);
        assertTrue(validator.isAccountWhitelisted(listId, account));

        ITestCreatorToken token = _deployNewToken(address(this));
        validator.applyListToCollection(address(token), listId);

        assertEq(validator.getWhitelistedAccountsByCollection(address(token)).length, 1);
        assertEq(validator.getWhitelistedAccountsByCollection(address(token))[0], account);
        assertTrue(validator.isAccountWhitelistedByCollection(address(token), account));

        //assertEq(token.getWhitelistedAccounts().length, 1);
        //assertEq(token.getWhitelistedAccounts()[0], account);
        //assertTrue(token.isAccountWhitelisted(account));
    }

    function testAddAccountsToWhitelist(address listOwner, address account1, address account2, address account3) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account1);
        _sanitizeAddress(account2);
        _sanitizeAddress(account3);
        vm.assume(account1 != account2);
        vm.assume(account1 != account3);
        vm.assume(account2 != account3);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](2);
        accounts[0] = account1;
        accounts[1] = account2;

        address[] memory accountsBatch2 = new address[](1);
        accountsBatch2[0] = account3;

        vm.startPrank(listOwner);
        validator.addAccountsToWhitelist(listId, accounts);
        validator.addAccountsToWhitelist(listId, accountsBatch2);
        vm.stopPrank();

        assertEq(validator.getWhitelistedAccounts(listId).length, 3);
        assertTrue(validator.isAccountWhitelisted(listId, account1));
        assertTrue(validator.isAccountWhitelisted(listId, account2));
        assertTrue(validator.isAccountWhitelisted(listId, account3));

        ITestCreatorToken token = _deployNewToken(address(this));
        validator.applyListToCollection(address(token), listId);

        assertEq(validator.getWhitelistedAccountsByCollection(address(token)).length, 3);
        assertTrue(validator.isAccountWhitelistedByCollection(address(token), account1));
        assertTrue(validator.isAccountWhitelistedByCollection(address(token), account2));
        assertTrue(validator.isAccountWhitelistedByCollection(address(token), account3));

        //assertEq(token.getWhitelistedAccounts().length, 3);
        //assertTrue(token.isAccountWhitelisted(account1));
        //assertTrue(token.isAccountWhitelisted(account2));
        //assertTrue(token.isAccountWhitelisted(account3));
    }

    function testRevertsWhenNonOwnerAddsCodehashToBlacklist(address listOwner, address unauthorizedUser, bytes32 codehash) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);
        
        vm.assume(codehash != bytes32(0));
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](1);
        codehashes[0] = codehash;

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addCodeHashesToBlacklist(listId, codehashes);
    }

    function testRevertsWhenBlacklistingEmptyCodehashArray(address listOwner) public {
        _sanitizeAddress(listOwner);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](0);

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__ArrayLengthCannotBeZero.selector);
        vm.prank(listOwner);
        validator.addCodeHashesToBlacklist(listId, codehashes);
    }

    function testRevertsWhenBlacklistingZeroHash(address listOwner, bytes32 codehash) public {
        _sanitizeAddress(listOwner);
        vm.assume(codehash != bytes32(0));
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](2);
        codehashes[0] = codehash;
        codehashes[1] = bytes32(0);

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__ZeroCodeHashNotAllowed.selector);
        vm.prank(listOwner);
        validator.addCodeHashesToBlacklist(listId, codehashes);
    }

    function testNoDuplicateCodehashesInBlacklist(address listOwner, bytes32 codehash) public {
        _sanitizeAddress(listOwner);
        vm.assume(codehash != bytes32(0));
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](3);
        codehashes[0] = codehash;
        codehashes[1] = codehash;
        codehashes[2] = codehash;

        vm.startPrank(listOwner);
        validator.addCodeHashesToBlacklist(listId, codehashes);
        validator.addCodeHashesToBlacklist(listId, codehashes);
        vm.stopPrank();

        assertEq(validator.getBlacklistedCodeHashes(listId).length, 1);
        assertEq(validator.getBlacklistedCodeHashes(listId)[0], codehash);
        assertTrue(validator.isCodeHashBlacklisted(listId, codehash));

        ITestCreatorToken token = _deployNewToken(address(this));
        validator.applyListToCollection(address(token), listId);

        assertEq(validator.getBlacklistedCodeHashesByCollection(address(token)).length, 1);
        assertEq(validator.getBlacklistedCodeHashesByCollection(address(token))[0], codehash);
        assertTrue(validator.isCodeHashBlacklistedByCollection(address(token), codehash));

        //assertEq(token.getBlacklistedCodeHashes().length, 1);
        //assertEq(token.getBlacklistedCodeHashes()[0], codehash);
        //assertTrue(token.isCodeHashBlacklisted(codehash));
    }

    function testAddCodeHashesToBlacklist(address listOwner, bytes32 codehash1, bytes32 codehash2, bytes32 codehash3) public {
        _sanitizeAddress(listOwner);
        vm.assume(codehash1 != bytes32(0));
        vm.assume(codehash2 != bytes32(0));
        vm.assume(codehash3 != bytes32(0));
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashesBatch1 = new bytes32[](2);
        codehashesBatch1[0] = codehash1;
        codehashesBatch1[1] = codehash2;

        bytes32[] memory codehashesBatch2 = new bytes32[](1);
        codehashesBatch2[0] = codehash3;

        vm.startPrank(listOwner);
        validator.addCodeHashesToBlacklist(listId, codehashesBatch1);
        validator.addCodeHashesToBlacklist(listId, codehashesBatch2);
        vm.stopPrank();

        assertEq(validator.getBlacklistedCodeHashes(listId).length, 3);
        assertTrue(validator.isCodeHashBlacklisted(listId, codehash1));
        assertTrue(validator.isCodeHashBlacklisted(listId, codehash2));
        assertTrue(validator.isCodeHashBlacklisted(listId, codehash3));

        ITestCreatorToken token = _deployNewToken(address(this));
        validator.applyListToCollection(address(token), listId);

        assertEq(validator.getBlacklistedCodeHashesByCollection(address(token)).length, 3);
        assertTrue(validator.isCodeHashBlacklistedByCollection(address(token), codehash1));
        assertTrue(validator.isCodeHashBlacklistedByCollection(address(token), codehash2));
        assertTrue(validator.isCodeHashBlacklistedByCollection(address(token), codehash3));

        //assertEq(token.getBlacklistedCodeHashes().length, 3);
        //assertTrue(token.isCodeHashBlacklisted(codehash1));
        //assertTrue(token.isCodeHashBlacklisted(codehash2));
        //assertTrue(token.isCodeHashBlacklisted(codehash3));
    }

    function testRevertsWhenNonOwnerAddsCodehashToWhitelist(address listOwner, address unauthorizedUser, bytes32 codehash) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);
        
        vm.assume(codehash != bytes32(0));
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](1);
        codehashes[0] = codehash;

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addCodeHashesToWhitelist(listId, codehashes);
    }

    function testRevertsWhenWhitelistingEmptyCodehashArray(address listOwner) public {
        _sanitizeAddress(listOwner);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](0);

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__ArrayLengthCannotBeZero.selector);
        vm.prank(listOwner);
        validator.addCodeHashesToWhitelist(listId, codehashes);
    }

    function testRevertsWhenWhitelistingZeroHash(address listOwner, bytes32 codehash) public {
        _sanitizeAddress(listOwner);
        vm.assume(codehash != bytes32(0));
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](2);
        codehashes[0] = codehash;
        codehashes[1] = bytes32(0);

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__ZeroCodeHashNotAllowed.selector);
        vm.prank(listOwner);
        validator.addCodeHashesToWhitelist(listId, codehashes);
    }

    function testNoDuplicateCodehashesInWhitelist(address listOwner, bytes32 codehash) public {
        _sanitizeAddress(listOwner);
        vm.assume(codehash != bytes32(0));
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](3);
        codehashes[0] = codehash;
        codehashes[1] = codehash;
        codehashes[2] = codehash;

        vm.startPrank(listOwner);
        validator.addCodeHashesToWhitelist(listId, codehashes);
        validator.addCodeHashesToWhitelist(listId, codehashes);
        vm.stopPrank();

        assertEq(validator.getWhitelistedCodeHashes(listId).length, 1);
        assertEq(validator.getWhitelistedCodeHashes(listId)[0], codehash);
        assertTrue(validator.isCodeHashWhitelisted(listId, codehash));

        ITestCreatorToken token = _deployNewToken(address(this));
        validator.applyListToCollection(address(token), listId);

        assertEq(validator.getWhitelistedCodeHashesByCollection(address(token)).length, 1);
        assertEq(validator.getWhitelistedCodeHashesByCollection(address(token))[0], codehash);
        assertTrue(validator.isCodeHashWhitelistedByCollection(address(token), codehash));

        //assertEq(token.getWhitelistedCodeHashes().length, 1);
        //assertEq(token.getWhitelistedCodeHashes()[0], codehash);
        //assertTrue(token.isCodeHashWhitelisted(codehash));
    }

    function testAddCodeHashesToWhitelist(address listOwner, bytes32 codehash1, bytes32 codehash2, bytes32 codehash3) public {
        _sanitizeAddress(listOwner);
        vm.assume(codehash1 != bytes32(0));
        vm.assume(codehash2 != bytes32(0));
        vm.assume(codehash3 != bytes32(0));
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashesBatch1 = new bytes32[](2);
        codehashesBatch1[0] = codehash1;
        codehashesBatch1[1] = codehash2;

        bytes32[] memory codehashesBatch2 = new bytes32[](1);
        codehashesBatch2[0] = codehash3;

        vm.startPrank(listOwner);
        validator.addCodeHashesToWhitelist(listId, codehashesBatch1);
        validator.addCodeHashesToWhitelist(listId, codehashesBatch2);
        vm.stopPrank();

        assertEq(validator.getWhitelistedCodeHashes(listId).length, 3);
        assertTrue(validator.isCodeHashWhitelisted(listId, codehash1));
        assertTrue(validator.isCodeHashWhitelisted(listId, codehash2));
        assertTrue(validator.isCodeHashWhitelisted(listId, codehash3));

        ITestCreatorToken token = _deployNewToken(address(this));
        validator.applyListToCollection(address(token), listId);

        assertEq(validator.getWhitelistedCodeHashesByCollection(address(token)).length, 3);
        assertTrue(validator.isCodeHashWhitelistedByCollection(address(token), codehash1));
        assertTrue(validator.isCodeHashWhitelistedByCollection(address(token), codehash2));
        assertTrue(validator.isCodeHashWhitelistedByCollection(address(token), codehash3));

        //assertEq(token.getWhitelistedCodeHashes().length, 3);
        //assertTrue(token.isCodeHashWhitelisted(codehash1));
        //assertTrue(token.isCodeHashWhitelisted(codehash2));
        //assertTrue(token.isCodeHashWhitelisted(codehash3));
    }

    //

    function testRevertsWhenNonOwnerRemovesAccountFromBlacklist(address listOwner, address unauthorizedUser, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        _sanitizeAddress(account);
        vm.assume(listOwner != unauthorizedUser);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](1);
        accounts[0] = account;

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.removeAccountsFromBlacklist(listId, accounts);
    }

    function testRevertsWhenUnblacklistingEmptyAccountArray(address listOwner) public {
        _sanitizeAddress(listOwner);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](0);

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__ArrayLengthCannotBeZero.selector);
        vm.prank(listOwner);
        validator.removeAccountsFromBlacklist(listId, accounts);
    }

    function testNoRevertWhenRemovingAddressesFromBlacklistIfTheyDoNotExist(address listOwner, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](3);
        accounts[0] = account;
        accounts[1] = account;
        accounts[2] = account;

        vm.startPrank(listOwner);
        validator.addAccountsToBlacklist(listId, accounts);
        validator.addAccountsToBlacklist(listId, accounts);
        vm.stopPrank();

        assertEq(validator.getBlacklistedAccounts(listId).length, 1);
        assertEq(validator.getBlacklistedAccounts(listId)[0], account);
        assertTrue(validator.isAccountBlacklisted(listId, account));

        vm.startPrank(listOwner);
        validator.removeAccountsFromBlacklist(listId, accounts);
        validator.removeAccountsFromBlacklist(listId, accounts);
        vm.stopPrank();

        assertEq(validator.getBlacklistedAccounts(listId).length, 0);
        assertFalse(validator.isAccountBlacklisted(listId, account));
    }

    function testRemoveAccountsFromBlacklist(address listOwner, address account1, address account2, address account3) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account1);
        _sanitizeAddress(account2);
        _sanitizeAddress(account3);
        vm.assume(account1 != account2);
        vm.assume(account2 != account3);
        vm.assume(account1 != account3);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](2);
        accounts[0] = account1;
        accounts[1] = account2;

        address[] memory accountsBatch2 = new address[](1);
        accountsBatch2[0] = account3;

        vm.startPrank(listOwner);
        validator.addAccountsToBlacklist(listId, accounts);
        validator.addAccountsToBlacklist(listId, accountsBatch2);
        vm.stopPrank();

        assertEq(validator.getBlacklistedAccounts(listId).length, 3);
        assertTrue(validator.isAccountBlacklisted(listId, account1));
        assertTrue(validator.isAccountBlacklisted(listId, account2));
        assertTrue(validator.isAccountBlacklisted(listId, account3));

        vm.startPrank(listOwner);
        validator.removeAccountsFromBlacklist(listId, accounts);
        validator.removeAccountsFromBlacklist(listId, accountsBatch2);
        vm.stopPrank();

        assertEq(validator.getBlacklistedAccounts(listId).length, 0);
        assertFalse(validator.isAccountBlacklisted(listId, account1));
        assertFalse(validator.isAccountBlacklisted(listId, account2));
        assertFalse(validator.isAccountBlacklisted(listId, account3));
    }

    function testRevertsWhenNonOwnerRemovesAccountFromWhitelist(address listOwner, address unauthorizedUser, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        _sanitizeAddress(account);
        vm.assume(listOwner != unauthorizedUser);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](1);
        accounts[0] = account;

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.removeAccountsFromWhitelist(listId, accounts);
    }

    function testRevertsWhenUnwhitelistingEmptyAccountArray(address listOwner) public {
        _sanitizeAddress(listOwner);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](0);

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__ArrayLengthCannotBeZero.selector);
        vm.prank(listOwner);
        validator.removeAccountsFromWhitelist(listId, accounts);
    }

    function testNoRevertWhenRemovingAddressesFromWhitelistIfTheyDoNotExist(address listOwner, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](3);
        accounts[0] = account;
        accounts[1] = account;
        accounts[2] = account;

        vm.startPrank(listOwner);
        validator.addAccountsToWhitelist(listId, accounts);
        validator.addAccountsToWhitelist(listId, accounts);
        vm.stopPrank();

        assertEq(validator.getWhitelistedAccounts(listId).length, 1);
        assertEq(validator.getWhitelistedAccounts(listId)[0], account);
        assertTrue(validator.isAccountWhitelisted(listId, account));

        vm.startPrank(listOwner);
        validator.removeAccountsFromWhitelist(listId, accounts);
        validator.removeAccountsFromWhitelist(listId, accounts);
        vm.stopPrank();

        assertEq(validator.getWhitelistedAccounts(listId).length, 0);
        assertFalse(validator.isAccountWhitelisted(listId, account));
    }

    function testRemoveAccountsFromWhitelist(address listOwner, address account1, address account2, address account3) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account1);
        _sanitizeAddress(account2);
        _sanitizeAddress(account3);
        vm.assume(account1 != account2);
        vm.assume(account2 != account3);
        vm.assume(account1 != account3);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](2);
        accounts[0] = account1;
        accounts[1] = account2;

        address[] memory accountsBatch2 = new address[](1);
        accountsBatch2[0] = account3;

        vm.startPrank(listOwner);
        validator.addAccountsToWhitelist(listId, accounts);
        validator.addAccountsToWhitelist(listId, accountsBatch2);
        vm.stopPrank();

        assertEq(validator.getWhitelistedAccounts(listId).length, 3);
        assertTrue(validator.isAccountWhitelisted(listId, account1));
        assertTrue(validator.isAccountWhitelisted(listId, account2));
        assertTrue(validator.isAccountWhitelisted(listId, account3));

        vm.startPrank(listOwner);
        validator.removeAccountsFromWhitelist(listId, accounts);
        validator.removeAccountsFromWhitelist(listId, accountsBatch2);
        vm.stopPrank();

        assertEq(validator.getWhitelistedAccounts(listId).length, 0);
        assertFalse(validator.isAccountWhitelisted(listId, account1));
        assertFalse(validator.isAccountWhitelisted(listId, account2));
        assertFalse(validator.isAccountWhitelisted(listId, account3));
    }

    // 

    function testRevertsWhenNonOwnerRemovesCodeHashFromBlacklist(address listOwner, address unauthorizedUser, bytes32 codehash) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](1);
        codehashes[0] = codehash;

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.removeCodeHashesFromBlacklist(listId, codehashes);
    }

    function testRevertsWhenUnblacklistingEmptyCodeHashArray(address listOwner) public {
        _sanitizeAddress(listOwner);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](0);

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__ArrayLengthCannotBeZero.selector);
        vm.prank(listOwner);
        validator.removeCodeHashesFromBlacklist(listId, codehashes);
    }

    function testNoRevertWhenRemovingCodeHashesFromBlacklistIfTheyDoNotExist(address listOwner, bytes32 codehash) public {
        _sanitizeAddress(listOwner);
        vm.assume(codehash != bytes32(0));
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](3);
        codehashes[0] = codehash;
        codehashes[1] = codehash;
        codehashes[2] = codehash;

        vm.startPrank(listOwner);
        validator.addCodeHashesToBlacklist(listId, codehashes);
        validator.addCodeHashesToBlacklist(listId, codehashes);
        vm.stopPrank();

        assertEq(validator.getBlacklistedCodeHashes(listId).length, 1);
        assertEq(validator.getBlacklistedCodeHashes(listId)[0], codehash);
        assertTrue(validator.isCodeHashBlacklisted(listId, codehash));

        vm.startPrank(listOwner);
        validator.removeCodeHashesFromBlacklist(listId, codehashes);
        validator.removeCodeHashesFromBlacklist(listId, codehashes);
        vm.stopPrank();

        assertEq(validator.getBlacklistedCodeHashes(listId).length, 0);
        assertFalse(validator.isCodeHashBlacklisted(listId, codehash));
    }

    function testRemoveCodeHashesFromBlacklist(address listOwner, bytes32 codehash1, bytes32 codehash2, bytes32 codehash3) public {
        _sanitizeAddress(listOwner);
        vm.assume(codehash1 != bytes32(0));
        vm.assume(codehash2 != bytes32(0));
        vm.assume(codehash3 != bytes32(0));
        vm.assume(codehash1 != codehash2);
        vm.assume(codehash2 != codehash3);
        vm.assume(codehash1 != codehash3);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashesBatch1 = new bytes32[](2);
        codehashesBatch1[0] = codehash1;
        codehashesBatch1[1] = codehash2;

        bytes32[] memory codehashesBatch2 = new bytes32[](1);
        codehashesBatch2[0] = codehash3;

        vm.startPrank(listOwner);
        validator.addCodeHashesToBlacklist(listId, codehashesBatch1);
        validator.addCodeHashesToBlacklist(listId, codehashesBatch2);
        vm.stopPrank();

        assertEq(validator.getBlacklistedCodeHashes(listId).length, 3);
        assertTrue(validator.isCodeHashBlacklisted(listId, codehash1));
        assertTrue(validator.isCodeHashBlacklisted(listId, codehash2));
        assertTrue(validator.isCodeHashBlacklisted(listId, codehash3));

        vm.startPrank(listOwner);
        validator.removeCodeHashesFromBlacklist(listId, codehashesBatch1);
        validator.removeCodeHashesFromBlacklist(listId, codehashesBatch2);
        vm.stopPrank();

        assertEq(validator.getBlacklistedCodeHashes(listId).length, 0);
        assertFalse(validator.isCodeHashBlacklisted(listId, codehash1));
        assertFalse(validator.isCodeHashBlacklisted(listId, codehash2));
        assertFalse(validator.isCodeHashBlacklisted(listId, codehash3));
    }

    function testRevertsWhenNonOwnerRemovesCodeHashFromWhitelist(address listOwner, address unauthorizedUser, bytes32 codehash) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](1);
        codehashes[0] = codehash;

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.removeCodeHashesFromWhitelist(listId, codehashes);
    }

    function testRevertsWhenUnwhitelistingEmptyCodeHashArray(address listOwner) public {
        _sanitizeAddress(listOwner);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](0);

        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__ArrayLengthCannotBeZero.selector);
        vm.prank(listOwner);
        validator.removeCodeHashesFromWhitelist(listId, codehashes);
    }

    function testNoRevertWhenRemovingCodeHashesFromWhitelistIfTheyDoNotExist(address listOwner, bytes32 codehash) public {
        _sanitizeAddress(listOwner);
        vm.assume(codehash != bytes32(0));
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](3);
        codehashes[0] = codehash;
        codehashes[1] = codehash;
        codehashes[2] = codehash;

        vm.startPrank(listOwner);
        validator.addCodeHashesToWhitelist(listId, codehashes);
        validator.addCodeHashesToWhitelist(listId, codehashes);
        vm.stopPrank();

        assertEq(validator.getWhitelistedCodeHashes(listId).length, 1);
        assertEq(validator.getWhitelistedCodeHashes(listId)[0], codehash);
        assertTrue(validator.isCodeHashWhitelisted(listId, codehash));

        vm.startPrank(listOwner);
        validator.removeCodeHashesFromWhitelist(listId, codehashes);
        validator.removeCodeHashesFromWhitelist(listId, codehashes);
        vm.stopPrank();

        assertEq(validator.getWhitelistedCodeHashes(listId).length, 0);
        assertFalse(validator.isCodeHashWhitelisted(listId, codehash));
    }

    function testRemoveCodeHashesFromWhitelist(address listOwner, bytes32 codehash1, bytes32 codehash2, bytes32 codehash3) public {
        _sanitizeAddress(listOwner);
        vm.assume(codehash1 != bytes32(0));
        vm.assume(codehash2 != bytes32(0));
        vm.assume(codehash3 != bytes32(0));
        vm.assume(codehash1 != codehash2);
        vm.assume(codehash2 != codehash3);
        vm.assume(codehash1 != codehash3);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashesBatch1 = new bytes32[](2);
        codehashesBatch1[0] = codehash1;
        codehashesBatch1[1] = codehash2;

        bytes32[] memory codehashesBatch2 = new bytes32[](1);
        codehashesBatch2[0] = codehash3;

        vm.startPrank(listOwner);
        validator.addCodeHashesToWhitelist(listId, codehashesBatch1);
        validator.addCodeHashesToWhitelist(listId, codehashesBatch2);
        vm.stopPrank();

        assertEq(validator.getWhitelistedCodeHashes(listId).length, 3);
        assertTrue(validator.isCodeHashWhitelisted(listId, codehash1));
        assertTrue(validator.isCodeHashWhitelisted(listId, codehash2));
        assertTrue(validator.isCodeHashWhitelisted(listId, codehash3));

        vm.startPrank(listOwner);
        validator.removeCodeHashesFromWhitelist(listId, codehashesBatch1);
        validator.removeCodeHashesFromWhitelist(listId, codehashesBatch2);
        vm.stopPrank();

        assertEq(validator.getWhitelistedCodeHashes(listId).length, 0);
        assertFalse(validator.isCodeHashWhitelisted(listId, codehash1));
        assertFalse(validator.isCodeHashWhitelisted(listId, codehash2));
        assertFalse(validator.isCodeHashWhitelisted(listId, codehash3));
    }

    function testBlacklistPoliciesWithOTCEnabledAllowTransfersWhenCalledByOwner(
        address creator,
        address tokenOwner,
        uint160 toKey
    ) public {
        address to = _verifyEOA(toKey);
        _testBlacklistPolicyAllowsTransfersWhenCalledByOwner(TransferSecurityLevels.One, creator, tokenOwner, to);
    }

    function testBlacklistPoliciesAllowAllTransfersWhenOperatorBlacklistIsEmpty(
        address creator,
        address caller,
        address from,
        uint160 toKey
    ) public {
        address to = _verifyEOA(toKey);
        _testPolicyAllowsAllTransfersWhenOperatorBlacklistIsEmpty(TransferSecurityLevels.One, creator, caller, from, to);
    }

    function testBlacklistPoliciesWithOTCEnabledBlockTransfersWhenCallerAccountBlacklistedAndNotOwner(
        address creator,
        address caller,
        address from,
        uint160 toKey
    ) public {
        _sanitizeAddress(caller);
        _sanitizeAddress(from);
        address to = _verifyEOA(toKey);
        _testPolicyBlocksTransfersWhenCallerAccountBlacklistedAndNotOwner(TransferSecurityLevels.Two, creator, caller, from, to);
    }

    function _testPolicyAllowsAllTransfersWhenOperatorBlacklistIsEmpty(
        TransferSecurityLevels level,
        address creator,
        address caller,
        address from,
        address to
    ) private {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.assume(caller != address(token));
        vm.assume(caller != address(0));
        vm.assume(from != address(0));
        vm.assume(from != caller);
        vm.assume(from != address(token));
        vm.assume(to != address(0));
        vm.assume(to != address(token));

        vm.startPrank(creator);

        uint120 listId = validator.createList("");

        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.applyListToCollection(address(token), listId);
        vm.stopPrank();

        assertTrue(token.isTransferAllowed(caller, from, to));

        _mintToken(address(token), from, 1);

        vm.prank(from);
        token.setApprovalForAll(caller, true);

        vm.prank(caller);
        token.transferFrom(from, to, 1);
        assertEq(token.ownerOf(1), to);
    }

    function _testPolicyBlocksTransfersWhenCallerAccountBlacklistedAndNotOwner(
        TransferSecurityLevels level,
        address creator,
        address caller,
        address from,
        address to
    ) private {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.assume(caller != address(token));
        vm.assume(caller != address(0));
        vm.assume(from != address(0));
        vm.assume(from != caller);
        vm.assume(from != address(token));
        vm.assume(to != address(0));
        vm.assume(to != address(token));

        address[] memory blacklistedAccounts = new address[](1);
        blacklistedAccounts[0] = caller;

        vm.startPrank(creator);
        uint120 listId = validator.createList("");
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.applyListToCollection(address(token), listId);
        validator.addAccountsToBlacklist(listId, blacklistedAccounts);
        vm.stopPrank();

        assertFalse(token.isTransferAllowed(caller, from, to));

        _mintToken(address(token), from, 1);

        vm.prank(from);
        token.setApprovalForAll(caller, true);

        vm.prank(caller);
        vm.expectRevert(
            CreatorTokenTransferValidator.CreatorTokenTransferValidator__OperatorIsBlacklisted.selector
        );
        token.transferFrom(from, to, 1);
    }

    function _testBlacklistPolicyAllowsTransfersWhenCalledByOwner(
        TransferSecurityLevels level,
        address creator,
        address tokenOwner,
        address to
    ) private {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.assume(tokenOwner != address(token));
        vm.assume(tokenOwner != address(0));
        vm.assume(to != address(0));
        vm.assume(to != address(token));

        address[] memory blacklistedAccounts = new address[](1);
        blacklistedAccounts[0] = tokenOwner;

        vm.startPrank(creator);
        uint120 listId = validator.createList("");
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.applyListToCollection(address(token), listId);
        validator.addAccountsToBlacklist(listId, blacklistedAccounts);
        vm.stopPrank();

        assertTrue(token.isTransferAllowed(tokenOwner, tokenOwner, to));

        _mintToken(address(token), tokenOwner, 1);

        vm.prank(tokenOwner);
        token.transferFrom(tokenOwner, to, 1);

        assertEq(token.ownerOf(1), to);
    }

    function testIsApprovedForAllDefaultsToFalseForTransferValidator(address creator, address owner) public {
        _sanitizeAddress(creator);
        _sanitizeAddress(owner);
        vm.assume(creator != owner);

        ITestCreatorToken token = _deployNewToken(creator);
        vm.prank(creator);
        token.setTransferValidator(address(validator));

        assertFalse(token.isApprovedForAll(owner, address(validator)));
    }

    function testIsApprovedForAllReturnsTrueForTransferValidatorIfAutoApproveEnabledByCreator(address creator, address owner) public {
        _sanitizeAddress(creator);
        _sanitizeAddress(owner);
        vm.assume(creator != owner);

        ITestCreatorToken token = _deployNewToken(creator);
        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        token.setAutomaticApprovalOfTransfersFromValidator(true);
        vm.stopPrank();

        assertTrue(token.isApprovedForAll(owner, address(validator)));
    }

    function testIsApprovedForAllReturnsTrueForDefaultTransferValidatorIfAutoApproveEnabledByCreatorAndValidatorUninitialized(address creator, address owner) public {
        _sanitizeAddress(creator);
        _sanitizeAddress(owner);
        vm.assume(creator != owner);

        ITestCreatorToken token = _deployNewToken(creator);
        vm.startPrank(creator);
        token.setAutomaticApprovalOfTransfersFromValidator(true);
        vm.stopPrank();

        assertTrue(token.isApprovedForAll(owner, token.DEFAULT_TRANSFER_VALIDATOR()));
    }

    function testIsApprovedForAllReturnsTrueWhenUserExplicitlyApprovesTransferValidator(address creator, address owner) public {
        _sanitizeAddress(creator);
        _sanitizeAddress(owner);
        vm.assume(creator != owner);

        ITestCreatorToken token = _deployNewToken(creator);
        vm.prank(creator);
        token.setTransferValidator(address(validator));

        vm.prank(owner);
        token.setApprovalForAll(address(validator), true);

        assertTrue(token.isApprovedForAll(owner, address(validator)));
    }
    */

    /*
// These Are Really Creator Token Tests

    function testGetTransferValidatorReturnsTransferValidatorAddressBeforeValidatorIsSet(address creator) public {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);
        assertEq(address(token.getTransferValidator()), token.DEFAULT_TRANSFER_VALIDATOR());
    }

    function testRevertsWhenSetTransferValidatorCalledWithContractThatDoesNotImplementRequiredInterface(address creator)
        public
    {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.startPrank(creator);
        address invalidContract = address(new ContractMock());
        vm.expectRevert(CreatorTokenBase.CreatorTokenBase__InvalidTransferValidatorContract.selector);
        token.setTransferValidator(invalidContract);
        vm.stopPrank();
    }

    function testAllowsAlternativeValidatorsToBeSetIfTheyImplementRequiredInterface(address creator) public {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.startPrank(creator);
        address alternativeValidator = address(new CreatorTokenTransferValidator(creator));
        token.setTransferValidator(alternativeValidator);
        vm.stopPrank();

        assertEq(address(token.getTransferValidator()), alternativeValidator);
    }

    function testAllowsValidatorToBeSetBackToZeroAddress(address creator) public {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.startPrank(creator);
        address alternativeValidator = address(new CreatorTokenTransferValidator(creator));
        token.setTransferValidator(alternativeValidator);
        token.setTransferValidator(address(0));
        vm.stopPrank();

        assertEq(address(token.getTransferValidator()), address(0));
    }

    function testGetSecurityPolicyReturnsRecommendedPolicyWhenNoValidatorIsSet(address creator) public {
        vm.assume(creator != address(0));
        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        CollectionSecurityPolicy memory securityPolicy = validator.getCollectionSecurityPolicy(address(token));
        assertEq(uint8(securityPolicy.transferSecurityLevel), uint8(TransferSecurityLevels.Recommended));
        assertEq(uint256(securityPolicy.operatorWhitelistId), 0);
        assertEq(uint256(securityPolicy.permittedContractReceiversId), 0);

        CollectionSecurityPolicy memory securityPolicy = validator.getCollectionSecurityPolicy(address(token));
        assertEq(uint8(securityPolicy.transferSecurityLevel), uint8(TransferSecurityLevels.Recommended));
        assertEq(uint256(securityPolicy.listId), 0);
    }

    function testGetSecurityPolicyReturnsEmptyPolicyWhenValidatorIsSetToZeroAddress(address creator) public {
        vm.assume(creator != address(0));
        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.prank(creator);
        token.setTransferValidator(address(0));

        CollectionSecurityPolicy memory securityPolicy = validator.getCollectionSecurityPolicy(address(token));
        assertEq(uint8(securityPolicy.transferSecurityLevel), uint8(TransferSecurityLevels.Recommended));
        assertEq(uint256(securityPolicy.operatorWhitelistId), 0);
        assertEq(uint256(securityPolicy.permittedContractReceiversId), 0);

        CollectionSecurityPolicy memory securityPolicy = validator.getCollectionSecurityPolicy(address(token));
        assertEq(uint8(securityPolicy.transferSecurityLevel), uint8(TransferSecurityLevels.Recommended));
        assertEq(uint256(securityPolicy.listId), 0);
    }

    function testGetSecurityPolicyReturnsExpectedSecurityPolicy(address creator, uint8 levelUint8) public {
        vm.assume(creator != address(0));
        vm.assume(levelUint8 >= 0 && levelUint8 <= 8);

        TransferSecurityLevels level = TransferSecurityLevels(levelUint8);

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.startPrank(creator);
        uint120 listId = validator.createList("");
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.applyListToCollection(address(token), listId);
        vm.stopPrank();

        CollectionSecurityPolicy memory securityPolicy = validator.getCollectionSecurityPolicy(address(token));
        assertTrue(securityPolicy.transferSecurityLevel == level);
        assertEq(uint256(securityPolicy.operatorWhitelistId), listId);
        assertEq(uint256(securityPolicy.permittedContractReceiversId), listId);

        CollectionSecurityPolicy memory securityPolicy = validator.getCollectionSecurityPolicy(address(token));
        assertTrue(securityPolicy.transferSecurityLevel == level);
        assertEq(uint256(securityPolicy.listId), listId);
    }

    function testSetCustomSecurityPolicy(address creator, uint8 levelUint8) public {
        vm.assume(creator != address(0));
        vm.assume(levelUint8 >= 0 && levelUint8 <= 8);

        TransferSecurityLevels level = TransferSecurityLevels(levelUint8);

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.startPrank(creator);
        uint120 operatorWhitelistId = validator.createOperatorWhitelist("");
        token.setToCustomValidatorAndSecurityPolicy(address(validator), level, operatorWhitelistId);
        vm.stopPrank();

        assertEq(address(token.getTransferValidator()), address(validator));

        CollectionSecurityPolicy memory securityPolicy = validator.getCollectionSecurityPolicy(address(token));
        assertTrue(securityPolicy.transferSecurityLevel == level);
        assertEq(uint256(securityPolicy.operatorWhitelistId), operatorWhitelistId);
        assertEq(uint256(securityPolicy.permittedContractReceiversId), operatorWhitelistId);

        CollectionSecurityPolicy memory securityPolicy = validator.getCollectionSecurityPolicy(address(token));
        assertTrue(securityPolicy.transferSecurityLevel == level);
        assertEq(uint256(securityPolicy.listId), operatorWhitelistId);
    }

    function testSetTransferSecurityLevelOfCollection(address creator, uint8 levelUint8) public {
        vm.assume(creator != address(0));
        vm.assume(levelUint8 >= 0 && levelUint8 <= 6);

        TransferSecurityLevels level = TransferSecurityLevels(levelUint8);

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.startPrank(creator);
        vm.expectEmit(true, false, false, true);
        emit SetTransferSecurityLevel(address(token), level);
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        vm.stopPrank();

        CollectionSecurityPolicy memory securityPolicy = validator.getCollectionSecurityPolicy(address(token));
        assertTrue(securityPolicy.transferSecurityLevel == level);
    }

    function testSetOperatorWhitelistOfCollection(address creator) public {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);
        vm.startPrank(creator);

        uint120 listId = validator.createOperatorWhitelist("test");

        vm.expectEmit(true, true, true, false);
        emit AppliedListToCollection(address(token), listId);

        validator.setOperatorWhitelistOfCollection(address(token), listId);
        vm.stopPrank();

        CollectionSecurityPolicy memory securityPolicy = validator.getCollectionSecurityPolicy(address(token));
        assertTrue(securityPolicy.operatorWhitelistId == listId);
    }

    function testRevertsWhenSettingOperatorWhitelistOfCollectionToInvalidListId(address creator, uint120 listId)
        public
    {
        vm.assume(creator != address(0));
        vm.assume(listId > 1);

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);
        vm.prank(creator);
        vm.expectRevert(CreatorTokenTransferValidator.CreatorTokenTransferValidator__ListDoesNotExist.selector);
        validator.setOperatorWhitelistOfCollection(address(token), listId);
    }

    function testRevertsWhenUnauthorizedUserSetsOperatorWhitelistOfCollection(address creator, address unauthorizedUser)
        public
    {
        vm.assume(creator != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(creator != unauthorizedUser);

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.assume(unauthorizedUser != address(token));

        vm.startPrank(unauthorizedUser);
        uint120 listId = validator.createOperatorWhitelist("naughty list");

        vm.expectRevert(
            CreatorTokenTransferValidator
                .CreatorTokenTransferValidator__CallerMustHaveElevatedPermissionsForSpecifiedNFT
                .selector
        );
        validator.setOperatorWhitelistOfCollection(address(token), listId);
        vm.stopPrank();
    }
    */
}
