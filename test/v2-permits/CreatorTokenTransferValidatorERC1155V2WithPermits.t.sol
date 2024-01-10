// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../v2/mocks/ClonerMock.sol";
import "../v2/mocks/ContractMock.sol";
import "../v2/mocks/ERC1155CMock.sol";
import "../v2/interfaces/ITestCreatorToken1155.sol";
import "src/utils/TransferPolicy.sol";
import "src/utils/CreatorTokenTransferValidatorWithPermits.sol";

contract CreatorTokenTransferValidatorERC1155V2WithPermitsTest is Test {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    event CreatedList(uint256 indexed id, string name);
    event AppliedListToCollection(address indexed collection, uint120 indexed id);
    event ReassignedListOwnership(uint256 indexed id, address indexed newOwner);
    event AddedAccountToList(ListTypes indexed kind, uint256 indexed id, address indexed account);
    event AddedCodeHashToList(ListTypes indexed kind, uint256 indexed id, bytes32 indexed codehash);
    event RemovedAccountFromList(ListTypes indexed kind, uint256 indexed id, address indexed account);
    event RemovedCodeHashFromList(ListTypes indexed kind, uint256 indexed id, bytes32 indexed codehash);
    event SetTransferSecurityLevel(address indexed collection, TransferSecurityLevels level);

    bytes32 private saltValue =
        bytes32(uint256(8946686101848117716489848979750688532688049124417468924436884748620307827805));

    CreatorTokenTransferValidatorWithPermits public validator;

    address validatorDeployer;
    address whitelistedOperator;

    function setUp() public virtual {
        validatorDeployer = vm.addr(1);
        vm.startPrank(validatorDeployer);
        validator = new CreatorTokenTransferValidatorWithPermits(validatorDeployer, "Test", "TST");
        vm.stopPrank();

        whitelistedOperator = vm.addr(2);

        vm.prank(validatorDeployer);
        validator.addOperatorToWhitelist(0, whitelistedOperator);
    }

    function _deployNewToken(address creator) internal virtual returns (ITestCreatorToken1155) {
        vm.prank(creator);
        return ITestCreatorToken1155(address(new ERC1155CMock()));
    }

    function _mintToken(address tokenAddress, address to, uint256 tokenId, uint256 amount) internal virtual {
        ERC1155CMock(tokenAddress).mint(to, tokenId, amount);
    }

    // function testV2DeterministicAddressForCreatorTokenValidator() public {
    //     assertEq(address(validator), 0xD679fBb2C884Eb28ED08B33e7095caFd63C76e99);
    // }

    function testV2TransferSecurityLevelRecommended() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.Recommended);
        assertEq(uint8(TransferSecurityLevels.Recommended), 0);
        assertTrue(callerConstraints == CallerConstraints.OperatorWhitelistEnableOTC);
        assertTrue(receiverConstraints == ReceiverConstraints.None);
    }

    function testV2TransferSecurityLevelOne() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.One);
        assertEq(uint8(TransferSecurityLevels.One), 1);
        assertTrue(callerConstraints == CallerConstraints.None);
        assertTrue(receiverConstraints == ReceiverConstraints.None);
    }

    function testV2TransferSecurityLevelTwo() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.Two);
        assertEq(uint8(TransferSecurityLevels.Two), 2);
        assertTrue(callerConstraints == CallerConstraints.OperatorBlacklistEnableOTC);
        assertTrue(receiverConstraints == ReceiverConstraints.None);
    }

    function testV2TransferSecurityLevelThree() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.Three);
        assertEq(uint8(TransferSecurityLevels.Three), 3);
        assertTrue(callerConstraints == CallerConstraints.OperatorWhitelistEnableOTC);
        assertTrue(receiverConstraints == ReceiverConstraints.None);
    }

    function testV2TransferSecurityLevelFour() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.Four);
        assertEq(uint8(TransferSecurityLevels.Four), 4);
        assertTrue(callerConstraints == CallerConstraints.OperatorWhitelistDisableOTC);
        assertTrue(receiverConstraints == ReceiverConstraints.None);
    }

    function testV2TransferSecurityLevelFive() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.Five);
        assertEq(uint8(TransferSecurityLevels.Five), 5);
        assertTrue(callerConstraints == CallerConstraints.OperatorWhitelistEnableOTC);
        assertTrue(receiverConstraints == ReceiverConstraints.NoCode);
    }

    function testV2TransferSecurityLevelSix() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.Six);
        assertEq(uint8(TransferSecurityLevels.Six), 6);
        assertTrue(callerConstraints == CallerConstraints.OperatorWhitelistEnableOTC);
        assertTrue(receiverConstraints == ReceiverConstraints.EOA);
    }

    function testV2TransferSecurityLevelSeven() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.Seven);
        assertEq(uint8(TransferSecurityLevels.Seven), 7);
        assertTrue(callerConstraints == CallerConstraints.OperatorWhitelistDisableOTC);
        assertTrue(receiverConstraints == ReceiverConstraints.NoCode);
    }

    function testV2TransferSecurityLevelEight() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.Eight);
        assertEq(uint8(TransferSecurityLevels.Eight), 8);
        assertTrue(callerConstraints == CallerConstraints.OperatorWhitelistDisableOTC);
        assertTrue(receiverConstraints == ReceiverConstraints.EOA);
    }

    function testV2CreateOperatorWhitelist(address listOwner, string memory name) public {
        vm.assume(listOwner != address(0));
        vm.assume(bytes(name).length < 200);

        uint120 firstListId = 1;
        for (uint120 i = 0; i < 5; ++i) {
            uint120 expectedId = firstListId + i;

            vm.expectEmit(true, true, true, false);
            emit CreatedList(expectedId, name);

            vm.expectEmit(true, true, true, false);
            emit ReassignedListOwnership(expectedId, listOwner);

            vm.prank(listOwner);
            uint120 actualId = validator.createOperatorWhitelist(name);
            assertEq(actualId, expectedId);
            assertEq(validator.listOwners(actualId), listOwner);
        }
    }

    function testV2ReassignOwnershipOfOperatorWhitelist(address originalListOwner, address newListOwner) public {
        vm.assume(originalListOwner != address(0));
        vm.assume(newListOwner != address(0));
        vm.assume(originalListOwner != newListOwner);

        vm.prank(originalListOwner);
        uint120 listId = validator.createOperatorWhitelist("test");
        assertEq(validator.listOwners(listId), originalListOwner);

        vm.expectEmit(true, true, true, false);
        emit ReassignedListOwnership(listId, newListOwner);

        vm.prank(originalListOwner);
        validator.reassignOwnershipOfOperatorWhitelist(listId, newListOwner);
        assertEq(validator.listOwners(listId), newListOwner);
    }

    function testV2RevertsWhenReassigningOwnershipOfOperatorWhitelistToZero(address originalListOwner) public {
        vm.assume(originalListOwner != address(0));

        vm.prank(originalListOwner);
        uint120 listId = validator.createOperatorWhitelist("test");
        assertEq(validator.listOwners(listId), originalListOwner);

        vm.expectRevert(
            CreatorTokenTransferValidatorWithPermits
                .CreatorTokenTransferValidator__ListOwnershipCannotBeTransferredToZeroAddress
                .selector
        );
        validator.reassignOwnershipOfOperatorWhitelist(listId, address(0));
    }

    function testV2RevertsWhenNonOwnerReassignsOwnershipOfOperatorWhitelist(
        address originalListOwner,
        address unauthorizedUser
    ) public {
        vm.assume(originalListOwner != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(originalListOwner != unauthorizedUser);

        vm.prank(originalListOwner);
        uint120 listId = validator.createOperatorWhitelist("test");
        assertEq(validator.listOwners(listId), originalListOwner);

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.reassignOwnershipOfOperatorWhitelist(listId, unauthorizedUser);
    }

    function testV2RenounceOwnershipOfOperatorWhitelist(address originalListOwner) public {
        vm.assume(originalListOwner != address(0));

        vm.prank(originalListOwner);
        uint120 listId = validator.createOperatorWhitelist("test");
        assertEq(validator.listOwners(listId), originalListOwner);

        vm.expectEmit(true, true, true, false);
        emit ReassignedListOwnership(listId, address(0));

        vm.prank(originalListOwner);
        validator.renounceOwnershipOfOperatorWhitelist(listId);
        assertEq(validator.listOwners(listId), address(0));
    }

    function testV2RevertsWhenNonOwnerRenouncesOwnershipOfOperatorWhitelist(
        address originalListOwner,
        address unauthorizedUser
    ) public {
        vm.assume(originalListOwner != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(originalListOwner != unauthorizedUser);

        vm.prank(originalListOwner);
        uint120 listId = validator.createOperatorWhitelist("test");
        assertEq(validator.listOwners(listId), originalListOwner);

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.renounceOwnershipOfOperatorWhitelist(listId);
    }

    function testV2GetTransferValidatorReturnsTransferValidatorV2AddressBeforeValidatorIsSet(address creator) public {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);
        assertEq(address(token.getTransferValidator()), token.DEFAULT_TRANSFER_VALIDATOR());
    }

    function testV2RevertsWhenSetTransferValidatorCalledWithContractThatDoesNotImplementRequiredInterface(address creator)
        public
    {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.startPrank(creator);
        address invalidContract = address(new ContractMock());
        vm.expectRevert(CreatorTokenBaseV2.CreatorTokenBase__InvalidTransferValidatorContract.selector);
        token.setTransferValidator(invalidContract);
        vm.stopPrank();
    }

    function testV2AllowsAlternativeValidatorsToBeSetIfTheyImplementRequiredInterface(address creator) public {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.startPrank(creator);
        address alternativeValidator = address(new CreatorTokenTransferValidatorWithPermits(creator, "", ""));
        token.setTransferValidator(alternativeValidator);
        vm.stopPrank();

        assertEq(address(token.getTransferValidator()), alternativeValidator);
    }

    function testV2AllowsValidatorToBeSetBackToZeroAddress(address creator) public {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.startPrank(creator);
        address alternativeValidator = address(new CreatorTokenTransferValidatorWithPermits(creator, "", ""));
        token.setTransferValidator(alternativeValidator);
        token.setTransferValidator(address(0));
        vm.stopPrank();

        assertEq(address(token.getTransferValidator()), address(0));
    }

    function testV2GetSecurityPolicyReturnsRecommendedPolicyWhenNoValidatorIsSet(address creator) public {
        vm.assume(creator != address(0));
        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);
        CollectionSecurityPolicy memory securityPolicy = validator.getCollectionSecurityPolicy(address(token));
        assertEq(uint8(securityPolicy.transferSecurityLevel), uint8(TransferSecurityLevels.Recommended));
        assertEq(uint256(securityPolicy.operatorWhitelistId), 0);
        assertEq(uint256(securityPolicy.permittedContractReceiversId), 0);
    }

    function testV2GetSecurityPolicyReturnsEmptyPolicyWhenValidatorIsSetToZeroAddress(address creator) public {
        vm.assume(creator != address(0));
        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.prank(creator);
        token.setTransferValidator(address(0));

        CollectionSecurityPolicy memory securityPolicy = validator.getCollectionSecurityPolicy(address(token));
        assertEq(uint8(securityPolicy.transferSecurityLevel), uint8(TransferSecurityLevels.Recommended));
        assertEq(uint256(securityPolicy.operatorWhitelistId), 0);
        assertEq(uint256(securityPolicy.permittedContractReceiversId), 0);
    }

    function testV2GetSecurityPolicyReturnsExpectedSecurityPolicy(address creator, uint8 levelUint8) public {
        vm.assume(creator != address(0));
        vm.assume(levelUint8 >= 0 && levelUint8 <= 8);

        TransferSecurityLevels level = TransferSecurityLevels(levelUint8);

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);

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

        CollectionSecurityPolicyV2 memory securityPolicyV2 = validator.getCollectionSecurityPolicyV2(address(token));
        assertTrue(securityPolicyV2.transferSecurityLevel == level);
        assertEq(uint256(securityPolicyV2.listId), listId);
    }

    function testV2SetCustomSecurityPolicy(address creator, uint8 levelUint8) public {
        vm.assume(creator != address(0));
        vm.assume(levelUint8 >= 0 && levelUint8 <= 8);

        TransferSecurityLevels level = TransferSecurityLevels(levelUint8);

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.startPrank(creator);
        uint120 operatorWhitelistId = validator.createOperatorWhitelist("");
        token.setToCustomValidatorAndSecurityPolicy(address(validator), level, operatorWhitelistId);
        vm.stopPrank();

        assertEq(address(token.getTransferValidator()), address(validator));

        CollectionSecurityPolicy memory securityPolicy = validator.getCollectionSecurityPolicy(address(token));
        assertTrue(securityPolicy.transferSecurityLevel == level);
        assertEq(uint256(securityPolicy.operatorWhitelistId), operatorWhitelistId);
        assertEq(uint256(securityPolicy.permittedContractReceiversId), operatorWhitelistId);

        CollectionSecurityPolicyV2 memory securityPolicyV2 = validator.getCollectionSecurityPolicyV2(address(token));
        assertTrue(securityPolicyV2.transferSecurityLevel == level);
        assertEq(uint256(securityPolicyV2.listId), operatorWhitelistId);
    }

    function testV2SetTransferSecurityLevelOfCollection(address creator, uint8 levelUint8) public {
        vm.assume(creator != address(0));
        vm.assume(levelUint8 >= 0 && levelUint8 <= 6);

        TransferSecurityLevels level = TransferSecurityLevels(levelUint8);

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.startPrank(creator);
        vm.expectEmit(true, false, false, true);
        emit SetTransferSecurityLevel(address(token), level);
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        vm.stopPrank();

        CollectionSecurityPolicy memory securityPolicy = validator.getCollectionSecurityPolicy(address(token));
        assertTrue(securityPolicy.transferSecurityLevel == level);
    }

    function testV2SetOperatorWhitelistOfCollection(address creator) public {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);
        vm.startPrank(creator);

        uint120 listId = validator.createOperatorWhitelist("test");

        vm.expectEmit(true, true, true, false);
        emit AppliedListToCollection(address(token), listId);

        validator.setOperatorWhitelistOfCollection(address(token), listId);
        vm.stopPrank();

        CollectionSecurityPolicy memory securityPolicy = validator.getCollectionSecurityPolicy(address(token));
        assertTrue(securityPolicy.operatorWhitelistId == listId);
    }

    function testV2RevertsWhenSettingOperatorWhitelistOfCollectionToInvalidListId(address creator, uint120 listId)
        public
    {
        vm.assume(creator != address(0));
        vm.assume(listId > 1);

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);
        vm.prank(creator);
        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__ListDoesNotExist.selector);
        validator.setOperatorWhitelistOfCollection(address(token), listId);
    }

    function testV2RevertsWhenUnauthorizedUserSetsOperatorWhitelistOfCollection(address creator, address unauthorizedUser)
        public
    {
        vm.assume(creator != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(creator != unauthorizedUser);

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.assume(unauthorizedUser != address(token));

        vm.startPrank(unauthorizedUser);
        uint120 listId = validator.createOperatorWhitelist("naughty list");

        vm.expectRevert(
            CreatorTokenTransferValidatorWithPermits
                .CreatorTokenTransferValidator__CallerMustHaveElevatedPermissionsForSpecifiedNFT
                .selector
        );
        validator.setOperatorWhitelistOfCollection(address(token), listId);
        vm.stopPrank();
    }

    function testV2AddToOperatorWhitelist(address originalListOwner, address operator) public {
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

    function testV2WhitelistedOperatorsCanBeQueriedOnCreatorTokens(
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
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.startPrank(creator);
        uint120 listId = validator.createOperatorWhitelist("");
        token.setTransferValidator(address(validator));
        validator.setOperatorWhitelistOfCollection(address(token), listId);
        validator.addOperatorToWhitelist(listId, operator1);
        validator.addOperatorToWhitelist(listId, operator2);
        validator.addOperatorToWhitelist(listId, operator3);
        vm.stopPrank();

        assertTrue(validator.isOperatorWhitelisted(validator.getCollectionSecurityPolicyV2(address(token)).listId, operator1));
        assertTrue(validator.isOperatorWhitelisted(validator.getCollectionSecurityPolicyV2(address(token)).listId, operator2));
        assertTrue(validator.isOperatorWhitelisted(validator.getCollectionSecurityPolicyV2(address(token)).listId, operator3));

        address[] memory allowedAddresses = validator.getWhitelistedOperators(validator.getCollectionSecurityPolicyV2(address(token)).listId);
        assertEq(allowedAddresses.length, 3);
        assertTrue(allowedAddresses[0] == operator1);
        assertTrue(allowedAddresses[1] == operator2);
        assertTrue(allowedAddresses[2] == operator3);
    }

    function testV2WhitelistedOperatorQueriesWhenUninitializedReturnsDefaultWhitelist(address creator, address operator) public {
        vm.assume(creator != address(0));
        vm.assume(operator != address(0));
        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);
        assertFalse(validator.isOperatorWhitelisted(validator.getCollectionSecurityPolicyV2(address(token)).listId, operator));
        address[] memory allowedAddresses = validator.getWhitelistedOperators(validator.getCollectionSecurityPolicyV2(address(token)).listId);
        assertEq(allowedAddresses.length, 1);
        assertEq(allowedAddresses[0], whitelistedOperator);
    }

    function testV2PermittedContractReceiversCanBeQueriedOnCreatorTokens(
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
        _sanitizeAddress(receiver1);
        _sanitizeAddress(receiver2);
        _sanitizeAddress(receiver3);
        ITestCreatorToken1155 token = _deployNewToken(creator);

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

        assertTrue(validator.isContractReceiverPermitted(validator.getCollectionSecurityPolicyV2(address(token)).listId, receiver1));
        assertTrue(validator.isContractReceiverPermitted(validator.getCollectionSecurityPolicyV2(address(token)).listId, receiver2));
        assertTrue(validator.isContractReceiverPermitted(validator.getCollectionSecurityPolicyV2(address(token)).listId, receiver3));

        validator.getCollectionSecurityPolicy(address(token));

        address[] memory allowedAddresses = validator.getPermittedContractReceivers(validator.getCollectionSecurityPolicyV2(address(token)).listId);
        assertEq(allowedAddresses.length, 3);
        assertTrue(allowedAddresses[0] == receiver1);
        assertTrue(allowedAddresses[1] == receiver2);
        assertTrue(allowedAddresses[2] == receiver3);
    }

    function testV2PermittedContractReceiverQueriesWhenNoTransferValidatorIsSet(address creator, address receiver)
        public
    {
        vm.assume(creator != address(0));
        vm.assume(receiver != address(0));
        vm.assume(receiver != whitelistedOperator);
        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);
        assertFalse(validator.isContractReceiverPermitted(validator.getCollectionSecurityPolicyV2(address(token)).listId, receiver));
        address[] memory allowedAddresses = validator.getPermittedContractReceivers(validator.getCollectionSecurityPolicyV2(address(token)).listId);
        assertEq(allowedAddresses.length, 1);
        assertEq(allowedAddresses[0], whitelistedOperator);
    }

    /*
    function testV2IsTransferAllowedReturnsFalseWhenNoTransferValidatorIsSet(
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
        ITestCreatorToken1155 token = _deployNewToken(creator);
        assertFalse(token.isTransferAllowed(caller, from, to));
    }
    */

    function testV2IsTransferAllowedReturnsTrueWhenTransferValidatorIsSetToZero(
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
        ITestCreatorToken1155 token = _deployNewToken(creator);
        
        vm.prank(creator);
        token.setTransferValidator(address(0));

        assertTrue(token.isTransferAllowed(caller, from, to));
    }

    function testV2RevertsWhenNonOwnerAddsOperatorToWhitelist(
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

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addOperatorToWhitelist(listId, operator);
    }

    function testV2WhenOperatorAddedToWhitelistAgainNoDuplicatesAreAdded(address originalListOwner, address operator) public {
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

    function testV2RemoveOperatorFromWhitelist(address originalListOwner, address operator) public {
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

    function testV2RevertsWhenUnwhitelistedOperatorRemovedFromWhitelist(address originalListOwner, address operator)
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

    function testV2AddManyOperatorsToWhitelist(address originalListOwner) public {
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

    function testV2SupportedInterfaces() public {
        assertEq(validator.supportsInterface(type(ITransferValidator).interfaceId), true);
        assertEq(validator.supportsInterface(type(ITransferSecurityRegistry).interfaceId), true);
        assertEq(validator.supportsInterface(type(ICreatorTokenTransferValidator).interfaceId), true);
        assertEq(validator.supportsInterface(type(IEOARegistry).interfaceId), true);
        assertEq(validator.supportsInterface(type(IERC165).interfaceId), true);
    }

    function testV2PolicyLevelOnePermitsAllTransfers(address creator, address caller, address from, address to) public {
        vm.assume(creator != address(0));
        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);
        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), TransferSecurityLevels.One);
        vm.stopPrank();
        assertTrue(token.isTransferAllowed(caller, from, to));
    }

    function testV2WhitelistPoliciesWithOTCEnabledBlockTransfersWhenCallerNotWhitelistedOrOwner(
        address creator,
        address caller,
        address from,
        uint160 toKey,
        uint256 tokenId,
        uint256 amount
    ) public {
        _sanitizeAddress(caller);
        _sanitizeAddress(from);
        address to = _verifyEOA(toKey);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Recommended, creator, caller, from, to, tokenId, amount);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Three, creator, caller, from, to, tokenId, amount);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Five, creator, caller, from, to, tokenId, amount);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Six, creator, caller, from, to, tokenId, amount);
    }

    function testV2WhitelistPoliciesWithOTCEnabledAllowTransfersWhenCalledByOwner(
        address creator,
        address tokenOwner,
        uint160 toKey,
        uint256 tokenId,
        uint256 amount
    ) public {
        address to = _verifyEOA(toKey);
        _testPolicyAllowsTransfersWhenCalledByOwner(TransferSecurityLevels.Recommended, creator, tokenOwner, to, tokenId, amount);
        _testPolicyAllowsTransfersWhenCalledByOwner(TransferSecurityLevels.Three, creator, tokenOwner, to, tokenId, amount);
        _testPolicyAllowsTransfersWhenCalledByOwner(TransferSecurityLevels.Five, creator, tokenOwner, to, tokenId, amount);
        _testPolicyAllowsTransfersWhenCalledByOwner(TransferSecurityLevels.Six, creator, tokenOwner, to, tokenId, amount);
    }

    function testV2WhitelistPoliciesWithOTCDisabledBlockTransfersWhenCallerNotWhitelistedOrOwner(
        address creator,
        address caller,
        address from,
        uint160 toKey,
        uint256 tokenId,
        uint256 amount
    ) public {
        address to = _verifyEOA(toKey);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Four, creator, caller, from, to, tokenId, amount);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Seven, creator, caller, from, to, tokenId, amount);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Eight, creator, caller, from, to, tokenId, amount);
    }

    function testV2WhitelistPoliciesWithOTCDisabledBlockTransfersWhenCalledByOwner(
        address creator,
        address tokenOwner,
        uint160 toKey,
        uint256 tokenId,
        uint256 amount
    ) public {
        address to = _verifyEOA(toKey);
        _testPolicyBlocksTransfersWhenCalledByOwner(TransferSecurityLevels.Four, creator, tokenOwner, to, tokenId, amount);
        _testPolicyBlocksTransfersWhenCalledByOwner(TransferSecurityLevels.Seven, creator, tokenOwner, to, tokenId, amount);
        _testPolicyBlocksTransfersWhenCalledByOwner(TransferSecurityLevels.Eight, creator, tokenOwner, to, tokenId, amount);
    }

    function testV2NoCodePoliciesBlockTransferWhenDestinationIsAContract(address creator, address caller, address from, uint256 tokenId, uint256 amount)
        public
    {
        _sanitizeAddress(caller);
        _sanitizeAddress(from);
        _testPolicyBlocksTransfersToContractReceivers(TransferSecurityLevels.Five, creator, caller, from, tokenId, amount);
        _testPolicyBlocksTransfersToContractReceivers(TransferSecurityLevels.Seven, creator, caller, from, tokenId, amount);
    }

    function testV2NoCodePoliciesAllowTransferToPermittedContractDestinations(
        address creator,
        address caller,
        address from,
        uint256 tokenId,
        uint256 amount
    ) public {
        _testPolicyAllowsTransfersToPermittedContractReceivers(TransferSecurityLevels.Four, creator, caller, from, tokenId, amount);
        _testPolicyAllowsTransfersToPermittedContractReceivers(TransferSecurityLevels.Six, creator, caller, from, tokenId, amount);
    }

    function testV2EOAPoliciesBlockTransferWhenDestinationHasNotVerifiedSignature(
        address creator,
        address caller,
        address from,
        address to,
        uint256 tokenId,
        uint256 amount
    ) public {
        _testPolicyBlocksTransfersToWalletsThatHaveNotVerifiedEOASignature(
            TransferSecurityLevels.Six, creator, caller, from, to, tokenId, amount
        );
        _testPolicyBlocksTransfersToWalletsThatHaveNotVerifiedEOASignature(
            TransferSecurityLevels.Eight, creator, caller, from, to, tokenId, amount
        );
    }

    function testV2EOAPoliciesAllowTransferWhenDestinationHasVerifiedSignature(
        address creator,
        address caller,
        address from,
        uint160 toKey,
        uint256 tokenId,
        uint256 amount
    ) public {
        address to = _verifyEOA(toKey);
        _testPolicyAllowsTransfersToWalletsThatHaveVerifiedEOASignature(
            TransferSecurityLevels.Five, creator, caller, from, to, tokenId, amount
        );
        _testPolicyAllowsTransfersToWalletsThatHaveVerifiedEOASignature(
            TransferSecurityLevels.Seven, creator, caller, from, to, tokenId, amount
        );
    }

    function testV2EOAPoliciesAllowTransferToPermittedContractDestinations(address creator, address caller, address from, uint256 tokenId, uint256 amount)
        public
    {
        _sanitizeAddress(caller);
        _sanitizeAddress(creator);
        _sanitizeAddress(from);
        _testPolicyAllowsTransfersToPermittedContractReceivers(TransferSecurityLevels.Six, creator, caller, from, tokenId, amount);
        _testPolicyAllowsTransfersToPermittedContractReceivers(TransferSecurityLevels.Eight, creator, caller, from, tokenId, amount);
    }

    function _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(
        TransferSecurityLevels level,
        address creator,
        address caller,
        address from,
        address to,
        uint256 tokenId,
        uint256 amount
    ) private {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.assume(caller != address(token));
        vm.assume(caller != whitelistedOperator);
        vm.assume(caller != address(0));
        vm.assume(from != address(0));
        vm.assume(from != caller);
        vm.assume(from != address(token));
        vm.assume(from.code.length == 0);
        vm.assume(to != address(0));
        vm.assume(to != address(token));
        vm.assume(to.code.length == 0);
        vm.assume(tokenId > 0);
        vm.assume(amount > 0);

        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.setOperatorWhitelistOfCollection(address(token), 0);
        vm.stopPrank();

        assertFalse(token.isTransferAllowed(caller, from, to));

        _mintToken(address(token), from, tokenId, amount);

        vm.prank(from);
        token.setApprovalForAll(caller, true);

        vm.prank(caller);
        vm.expectRevert(
            CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector
        );
        token.safeTransferFrom(from, to, tokenId, amount, "");
    }

    function _testPolicyAllowsTransfersWhenCalledByOwner(
        TransferSecurityLevels level,
        address creator,
        address tokenOwner,
        address to,
        uint256 tokenId,
        uint256 amount
    ) private {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.assume(tokenOwner != address(token));
        vm.assume(tokenOwner != whitelistedOperator);
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner.code.length == 0);
        vm.assume(to != address(0));
        vm.assume(to != address(token));
        vm.assume(tokenId > 0);
        vm.assume(amount > 0);

        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.setOperatorWhitelistOfCollection(address(token), 0);
        vm.stopPrank();

        assertTrue(token.isTransferAllowed(tokenOwner, tokenOwner, to));

        _mintToken(address(token), tokenOwner, tokenId, amount);

        vm.prank(tokenOwner);
        token.safeTransferFrom(tokenOwner, to, tokenId, amount, "");

        assertEq(token.balanceOf(to, tokenId), amount);
    }

    function _testPolicyBlocksTransfersWhenCalledByOwner(
        TransferSecurityLevels level,
        address creator,
        address tokenOwner,
        address to,
        uint256 tokenId,
        uint256 amount
    ) private {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.assume(tokenOwner != address(token));
        vm.assume(tokenOwner != whitelistedOperator);
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner.code.length == 0);
        vm.assume(to != address(0));
        vm.assume(to != address(token));
        vm.assume(tokenId > 0);
        vm.assume(amount > 0);

        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.setOperatorWhitelistOfCollection(address(token), 0);
        vm.stopPrank();

        assertFalse(token.isTransferAllowed(tokenOwner, tokenOwner, to));

        _mintToken(address(token), tokenOwner, tokenId, amount);

        vm.prank(tokenOwner);
        vm.expectRevert(
            CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector
        );
        token.safeTransferFrom(tokenOwner, to, tokenId, amount, "");
    }

    function _testPolicyBlocksTransfersToContractReceivers(
        TransferSecurityLevels level,
        address creator,
        address caller,
        address from,
        uint256 tokenId,
        uint256 amount
    ) private {
        vm.assume(creator != address(0));

        if (!validator.isOperatorWhitelisted(0, caller)) {
            vm.prank(validatorDeployer);
            validator.addOperatorToWhitelist(0, caller);
        }

        vm.prank(creator);
        address to = address(new ContractMock());

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.assume(caller != address(token));
        vm.assume(from != address(0));
        vm.assume(from != address(token));
        vm.assume(from.code.length == 0);
        vm.assume(tokenId > 0);
        vm.assume(amount > 0);

        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.setOperatorWhitelistOfCollection(address(token), 0);
        vm.stopPrank();

        assertFalse(token.isTransferAllowed(caller, from, to));

        _mintToken(address(token), from, tokenId, amount);

        if (caller != from) {
            vm.prank(from);
            token.setApprovalForAll(caller, true);
        }

        vm.prank(caller);
        vm.expectRevert(
            CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__ReceiverMustNotHaveDeployedCode.selector
        );
        token.safeTransferFrom(from, to, tokenId, amount, "");
    }

    function _testPolicyBlocksTransfersToWalletsThatHaveNotVerifiedEOASignature(
        TransferSecurityLevels level,
        address creator,
        address caller,
        address from,
        address to,
        uint256 tokenId,
        uint256 amount
    ) private {
        vm.assume(creator != address(0));

        if (!validator.isOperatorWhitelisted(0, caller)) {
            vm.prank(validatorDeployer);
            validator.addOperatorToWhitelist(0, caller);
        }

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.assume(caller != address(token));
        vm.assume(caller != address(0));
        vm.assume(from != address(0));
        vm.assume(from != address(token));
        vm.assume(from.code.length == 0);
        vm.assume(to != address(0));
        vm.assume(to != address(token));
        vm.assume(to != whitelistedOperator);
        vm.assume(to.code.length == 0);
        vm.assume(tokenId > 0);
        vm.assume(amount > 0);

        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.setOperatorWhitelistOfCollection(address(token), 0);
        vm.stopPrank();

        assertFalse(token.isTransferAllowed(caller, from, to));

        _mintToken(address(token), from, tokenId, amount);

        if (caller != from) {
            vm.prank(from);
            token.setApprovalForAll(caller, true);
        }

        vm.prank(caller);
        vm.expectRevert(
            CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__ReceiverProofOfEOASignatureUnverified.selector
        );
        token.safeTransferFrom(from, to, tokenId, amount, "");
    }

    function _testPolicyAllowsTransfersToWalletsThatHaveVerifiedEOASignature(
        TransferSecurityLevels level,
        address creator,
        address caller,
        address from,
        address to,
        uint256 tokenId,
        uint256 amount
    ) private {
        vm.assume(creator != address(0));

        if (!validator.isOperatorWhitelisted(0, caller)) {
            vm.prank(validatorDeployer);
            validator.addOperatorToWhitelist(0, caller);
        }

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.assume(caller != address(token));
        vm.assume(caller != address(0));
        vm.assume(from != address(0));
        vm.assume(from != address(token));
        vm.assume(to != address(0));
        vm.assume(to != address(token));
        vm.assume(from.code.length == 0);
        vm.assume(to.code.length == 0);
        vm.assume(tokenId > 0);
        vm.assume(amount > 0);

        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.setOperatorWhitelistOfCollection(address(token), 0);
        vm.stopPrank();

        assertTrue(token.isTransferAllowed(caller, from, to));

        _mintToken(address(token), from, tokenId, amount);

        if (caller != from) {
            vm.prank(from);
            token.setApprovalForAll(caller, true);
        }

        vm.prank(caller);
        token.safeTransferFrom(from, to, tokenId, amount, "");
        assertEq(token.balanceOf(to, tokenId), amount);
    }

    function _testPolicyAllowsTransfersToPermittedContractReceivers(
        TransferSecurityLevels level,
        address creator,
        address caller,
        address from,
        uint256 tokenId,
        uint256 amount
    ) private {
        vm.assume(creator != address(0));

        vm.prank(creator);
        address to = address(new ContractMock());

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.assume(caller != address(token));
        vm.assume(from != address(0));
        vm.assume(from != address(token));
        vm.assume(from.code.length == 0);
        vm.assume(tokenId > 0);
        vm.assume(amount > 0);

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

        _mintToken(address(token), from, tokenId, amount);

        if (caller != from) {
            vm.prank(from);
            token.setApprovalForAll(caller, true);
        }

        vm.prank(caller);
        token.safeTransferFrom(from, to, tokenId, amount, "");
        assertEq(token.balanceOf(to, tokenId), amount);
    }

    function _verifyEOA(uint160 toKey) internal returns (address to) {
        vm.assume(toKey > 0 && toKey < type(uint160).max);
        to = vm.addr(toKey);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(toKey, ECDSA.toEthSignedMessageHash(bytes(validator.MESSAGE_TO_SIGN())));
        vm.prank(to);
        validator.verifySignatureVRS(v, r, s);
    }

    function _sanitizeAddress(address addr) internal view virtual {
        vm.assume(addr.code.length == 0);
        vm.assume(uint160(addr) > 0xFF);
        vm.assume(addr != address(0));
        vm.assume(addr != address(0x000000000000000000636F6e736F6c652e6c6f67));
        vm.assume(addr != address(0xDDc10602782af652bB913f7bdE1fD82981Db7dd9));
    }

    function testV2CreateList(address listOwner, string memory name) public {
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

    function testV2CreateListCopy(address listOwnerSource, address listOwnerTarget, string memory nameSource, string memory nameTarget) public {
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

    function testV2ListCopyRevertsWhenCopyingANonExistentList(uint120 sourceListId) public {
        vm.assume(sourceListId > validator.lastListId());
        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__ListDoesNotExist.selector);
        validator.createListCopy("", sourceListId);
    }

    function testV2ReassignOwnershipOfList(address originalListOwner, address newListOwner) public {
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

    function testV2RevertsWhenReassigningOwnershipOfListToZero(address originalListOwner) public {
        vm.assume(originalListOwner != address(0));

        vm.prank(originalListOwner);
        uint120 listId = validator.createList("test");
        assertEq(validator.listOwners(listId), originalListOwner);

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__ListOwnershipCannotBeTransferredToZeroAddress.selector);
        validator.reassignOwnershipOfList(listId, address(0));
    }

    function testV2RenounceOwnershipOfList(address originalListOwner) public {
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

    function testV2RevertsWhenNonOwnerRenouncesOwnershipOfList(
        address originalListOwner,
        address unauthorizedUser
    ) public {
        vm.assume(originalListOwner != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(originalListOwner != unauthorizedUser);

        vm.prank(originalListOwner);
        uint120 listId = validator.createList("test");
        assertEq(validator.listOwners(listId), originalListOwner);

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.renounceOwnershipOfList(listId);
    }

    function testV2RevertsWhenNonOwnerAddsAccountToBlacklist(address listOwner, address unauthorizedUser, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        _sanitizeAddress(account);
        vm.assume(listOwner != unauthorizedUser);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](1);
        accounts[0] = account;

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addAccountsToBlacklist(listId, accounts);
    }

    function testV2RevertsWhenBlacklistingEmptyAccountArray(address listOwner) public {
        _sanitizeAddress(listOwner);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](0);

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__ArrayLengthCannotBeZero.selector);
        vm.prank(listOwner);
        validator.addAccountsToBlacklist(listId, accounts);
    }

    function testV2RevertsWhenBlacklistingZeroAddress(address listOwner, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](2);
        accounts[0] = account;
        accounts[1] = address(0);

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__ZeroAddressNotAllowed.selector);
        vm.prank(listOwner);
        validator.addAccountsToBlacklist(listId, accounts);
    }

    function testV2NoDuplicateAddressesInBlacklist(address listOwner, address account) public {
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

        ITestCreatorToken1155 token = _deployNewToken(address(this));
        validator.applyListToCollection(address(token), listId);

        assertEq(validator.getBlacklistedAccountsByCollection(address(token)).length, 1);
        assertEq(validator.getBlacklistedAccountsByCollection(address(token))[0], account);
        assertTrue(validator.isAccountBlacklistedByCollection(address(token), account));

        //assertEq(token.getBlacklistedAccounts().length, 1);
        //assertEq(token.getBlacklistedAccounts()[0], account);
        //assertTrue(token.isAccountBlacklisted(account));
    }

    function testV2AddAccountsToBlacklist(address listOwner, address account1, address account2, address account3) public {
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

        ITestCreatorToken1155 token = _deployNewToken(address(this));
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

    function testV2RevertsWhenNonOwnerAddsAccountToWhitelist(address listOwner, address unauthorizedUser, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        _sanitizeAddress(account);
        vm.assume(listOwner != unauthorizedUser);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](1);
        accounts[0] = account;

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addAccountsToWhitelist(listId, accounts);
    }

    function testV2RevertsWhenWhitelistingEmptyAccountArray(address listOwner) public {
        _sanitizeAddress(listOwner);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](0);

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__ArrayLengthCannotBeZero.selector);
        vm.prank(listOwner);
        validator.addAccountsToWhitelist(listId, accounts);
    }

    function testV2RevertsWhenWhitelistingZeroAddress(address listOwner, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(account);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](2);
        accounts[0] = account;
        accounts[1] = address(0);

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__ZeroAddressNotAllowed.selector);
        vm.prank(listOwner);
        validator.addAccountsToWhitelist(listId, accounts);
    }

    function testV2NoDuplicateAddressesInWhitelist(address listOwner, address account) public {
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

        ITestCreatorToken1155 token = _deployNewToken(address(this));
        validator.applyListToCollection(address(token), listId);

        assertEq(validator.getWhitelistedAccountsByCollection(address(token)).length, 1);
        assertEq(validator.getWhitelistedAccountsByCollection(address(token))[0], account);
        assertTrue(validator.isAccountWhitelistedByCollection(address(token), account));

        //assertEq(token.getWhitelistedAccounts().length, 1);
        //assertEq(token.getWhitelistedAccounts()[0], account);
        //assertTrue(token.isAccountWhitelisted(account));
    }

    function testV2AddAccountsToWhitelist(address listOwner, address account1, address account2, address account3) public {
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

        ITestCreatorToken1155 token = _deployNewToken(address(this));
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

    function testV2RevertsWhenNonOwnerAddsCodehashToBlacklist(address listOwner, address unauthorizedUser, bytes32 codehash) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);
        
        vm.assume(codehash != bytes32(0));
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](1);
        codehashes[0] = codehash;

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addCodeHashesToBlacklist(listId, codehashes);
    }

    function testV2RevertsWhenBlacklistingEmptyCodehashArray(address listOwner) public {
        _sanitizeAddress(listOwner);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](0);

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__ArrayLengthCannotBeZero.selector);
        vm.prank(listOwner);
        validator.addCodeHashesToBlacklist(listId, codehashes);
    }

    function testV2RevertsWhenBlacklistingZeroHash(address listOwner, bytes32 codehash) public {
        _sanitizeAddress(listOwner);
        vm.assume(codehash != bytes32(0));
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](2);
        codehashes[0] = codehash;
        codehashes[1] = bytes32(0);

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__ZeroCodeHashNotAllowed.selector);
        vm.prank(listOwner);
        validator.addCodeHashesToBlacklist(listId, codehashes);
    }

    function testV2NoDuplicateCodehashesInBlacklist(address listOwner, bytes32 codehash) public {
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

        ITestCreatorToken1155 token = _deployNewToken(address(this));
        validator.applyListToCollection(address(token), listId);

        assertEq(validator.getBlacklistedCodeHashesByCollection(address(token)).length, 1);
        assertEq(validator.getBlacklistedCodeHashesByCollection(address(token))[0], codehash);
        assertTrue(validator.isCodeHashBlacklistedByCollection(address(token), codehash));

        //assertEq(token.getBlacklistedCodeHashes().length, 1);
        //assertEq(token.getBlacklistedCodeHashes()[0], codehash);
        //assertTrue(token.isCodeHashBlacklisted(codehash));
    }

    function testV2AddCodeHashesToBlacklist(address listOwner, bytes32 codehash1, bytes32 codehash2, bytes32 codehash3) public {
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

        ITestCreatorToken1155 token = _deployNewToken(address(this));
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

    function testV2RevertsWhenNonOwnerAddsCodehashToWhitelist(address listOwner, address unauthorizedUser, bytes32 codehash) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);
        
        vm.assume(codehash != bytes32(0));
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](1);
        codehashes[0] = codehash;

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.addCodeHashesToWhitelist(listId, codehashes);
    }

    function testV2RevertsWhenWhitelistingEmptyCodehashArray(address listOwner) public {
        _sanitizeAddress(listOwner);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](0);

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__ArrayLengthCannotBeZero.selector);
        vm.prank(listOwner);
        validator.addCodeHashesToWhitelist(listId, codehashes);
    }

    function testV2RevertsWhenWhitelistingZeroHash(address listOwner, bytes32 codehash) public {
        _sanitizeAddress(listOwner);
        vm.assume(codehash != bytes32(0));
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](2);
        codehashes[0] = codehash;
        codehashes[1] = bytes32(0);

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__ZeroCodeHashNotAllowed.selector);
        vm.prank(listOwner);
        validator.addCodeHashesToWhitelist(listId, codehashes);
    }

    function testV2NoDuplicateCodehashesInWhitelist(address listOwner, bytes32 codehash) public {
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

        ITestCreatorToken1155 token = _deployNewToken(address(this));
        validator.applyListToCollection(address(token), listId);

        assertEq(validator.getWhitelistedCodeHashesByCollection(address(token)).length, 1);
        assertEq(validator.getWhitelistedCodeHashesByCollection(address(token))[0], codehash);
        assertTrue(validator.isCodeHashWhitelistedByCollection(address(token), codehash));

        //assertEq(token.getWhitelistedCodeHashes().length, 1);
        //assertEq(token.getWhitelistedCodeHashes()[0], codehash);
        //assertTrue(token.isCodeHashWhitelisted(codehash));
    }

    function testV2AddCodeHashesToWhitelist(address listOwner, bytes32 codehash1, bytes32 codehash2, bytes32 codehash3) public {
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

        ITestCreatorToken1155 token = _deployNewToken(address(this));
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

    function testV2RevertsWhenNonOwnerRemovesAccountFromBlacklist(address listOwner, address unauthorizedUser, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        _sanitizeAddress(account);
        vm.assume(listOwner != unauthorizedUser);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](1);
        accounts[0] = account;

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.removeAccountsFromBlacklist(listId, accounts);
    }

    function testV2RevertsWhenUnblacklistingEmptyAccountArray(address listOwner) public {
        _sanitizeAddress(listOwner);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](0);

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__ArrayLengthCannotBeZero.selector);
        vm.prank(listOwner);
        validator.removeAccountsFromBlacklist(listId, accounts);
    }

    function testV2NoRevertWhenRemovingAddressesFromBlacklistIfTheyDoNotExist(address listOwner, address account) public {
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

    function testV2RemoveAccountsFromBlacklist(address listOwner, address account1, address account2, address account3) public {
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

    function testV2RevertsWhenNonOwnerRemovesAccountFromWhitelist(address listOwner, address unauthorizedUser, address account) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        _sanitizeAddress(account);
        vm.assume(listOwner != unauthorizedUser);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](1);
        accounts[0] = account;

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.removeAccountsFromWhitelist(listId, accounts);
    }

    function testV2RevertsWhenUnwhitelistingEmptyAccountArray(address listOwner) public {
        _sanitizeAddress(listOwner);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        address[] memory accounts = new address[](0);

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__ArrayLengthCannotBeZero.selector);
        vm.prank(listOwner);
        validator.removeAccountsFromWhitelist(listId, accounts);
    }

    function testV2NoRevertWhenRemovingAddressesFromWhitelistIfTheyDoNotExist(address listOwner, address account) public {
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

    function testV2RemoveAccountsFromWhitelist(address listOwner, address account1, address account2, address account3) public {
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

    function testV2RevertsWhenNonOwnerRemovesCodeHashFromBlacklist(address listOwner, address unauthorizedUser, bytes32 codehash) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](1);
        codehashes[0] = codehash;

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.removeCodeHashesFromBlacklist(listId, codehashes);
    }

    function testV2RevertsWhenUnblacklistingEmptyCodeHashArray(address listOwner) public {
        _sanitizeAddress(listOwner);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](0);

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__ArrayLengthCannotBeZero.selector);
        vm.prank(listOwner);
        validator.removeCodeHashesFromBlacklist(listId, codehashes);
    }

    function testV2NoRevertWhenRemovingCodeHashesFromBlacklistIfTheyDoNotExist(address listOwner, bytes32 codehash) public {
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

    function testV2RemoveCodeHashesFromBlacklist(address listOwner, bytes32 codehash1, bytes32 codehash2, bytes32 codehash3) public {
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

    function testV2RevertsWhenNonOwnerRemovesCodeHashFromWhitelist(address listOwner, address unauthorizedUser, bytes32 codehash) public {
        _sanitizeAddress(listOwner);
        _sanitizeAddress(unauthorizedUser);
        vm.assume(listOwner != unauthorizedUser);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](1);
        codehashes[0] = codehash;

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.removeCodeHashesFromWhitelist(listId, codehashes);
    }

    function testV2RevertsWhenUnwhitelistingEmptyCodeHashArray(address listOwner) public {
        _sanitizeAddress(listOwner);
        
        vm.prank(listOwner);
        uint120 listId = validator.createList("test");

        bytes32[] memory codehashes = new bytes32[](0);

        vm.expectRevert(CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__ArrayLengthCannotBeZero.selector);
        vm.prank(listOwner);
        validator.removeCodeHashesFromWhitelist(listId, codehashes);
    }

    function testV2NoRevertWhenRemovingCodeHashesFromWhitelistIfTheyDoNotExist(address listOwner, bytes32 codehash) public {
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

    function testV2RemoveCodeHashesFromWhitelist(address listOwner, bytes32 codehash1, bytes32 codehash2, bytes32 codehash3) public {
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

    function testV2BlacklistPoliciesWithOTCEnabledAllowTransfersWhenCalledByOwner(
        address creator,
        address tokenOwner,
        uint160 toKey,
        uint256 tokenId, 
        uint256 amount
    ) public {
        address to = _verifyEOA(toKey);
        _testBlacklistPolicyAllowsTransfersWhenCalledByOwner(TransferSecurityLevels.One, creator, tokenOwner, to, tokenId, amount);
    }

    function testV2BlacklistPoliciesAllowAllTransfersWhenOperatorBlacklistIsEmpty(
        address creator,
        address caller,
        address from,
        uint160 toKey,
        uint256 tokenId, 
        uint256 amount
    ) public {
        address to = _verifyEOA(toKey);
        _testPolicyAllowsAllTransfersWhenOperatorBlacklistIsEmpty(TransferSecurityLevels.One, creator, caller, from, to, tokenId, amount);
    }

    function testV2BlacklistPoliciesWithOTCEnabledBlockTransfersWhenCallerAccountBlacklistedAndNotOwner(
        address creator,
        address caller,
        address from,
        uint160 toKey,
        uint256 tokenId,
        uint256 amount
    ) public {
        _sanitizeAddress(caller);
        _sanitizeAddress(from);
        address to = _verifyEOA(toKey);
        _testPolicyBlocksTransfersWhenCallerAccountBlacklistedAndNotOwner(TransferSecurityLevels.Two, creator, caller, from, to, tokenId, amount);
    }

    function _testPolicyAllowsAllTransfersWhenOperatorBlacklistIsEmpty(
        TransferSecurityLevels level,
        address creator,
        address caller,
        address from,
        address to,
        uint256 tokenId, 
        uint256 amount
    ) private {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        _sanitizeAddress(to);
        _sanitizeAddress(from);
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.assume(caller != address(token));
        vm.assume(caller != address(0));
        vm.assume(from != address(0));
        vm.assume(from != caller);
        vm.assume(from != address(token));
        vm.assume(to != address(0));
        vm.assume(to != address(token));
        vm.assume(tokenId > 0);
        vm.assume(amount > 0);

        vm.startPrank(creator);

        uint120 listId = validator.createList("");

        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), level);
        validator.applyListToCollection(address(token), listId);
        vm.stopPrank();

        assertTrue(token.isTransferAllowed(caller, from, to));

        _mintToken(address(token), from, tokenId, amount);

        vm.prank(from);
        token.setApprovalForAll(caller, true);

        vm.prank(caller);
        token.safeTransferFrom(from, to, tokenId, amount, "");
        assertEq(token.balanceOf(to, tokenId), amount);
    }

    function _testPolicyBlocksTransfersWhenCallerAccountBlacklistedAndNotOwner(
        TransferSecurityLevels level,
        address creator,
        address caller,
        address from,
        address to,
        uint256 tokenId, 
        uint256 amount
    ) private {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.assume(caller != address(token));
        vm.assume(caller != address(0));
        vm.assume(from != address(0));
        vm.assume(from != caller);
        vm.assume(from != address(token));
        vm.assume(to != address(0));
        vm.assume(to != address(token));
        vm.assume(tokenId > 0);
        vm.assume(amount > 0);

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

        _mintToken(address(token), from, tokenId, amount);

        vm.prank(from);
        token.setApprovalForAll(caller, true);

        vm.prank(caller);
        vm.expectRevert(
            CreatorTokenTransferValidatorWithPermits.CreatorTokenTransferValidator__OperatorIsBlacklisted.selector
        );
        token.safeTransferFrom(from, to, tokenId, amount, "");
    }

    function _testBlacklistPolicyAllowsTransfersWhenCalledByOwner(
        TransferSecurityLevels level,
        address creator,
        address tokenOwner,
        address to,
        uint256 tokenId,
        uint256 amount
    ) private {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        _sanitizeAddress(tokenOwner);
        _sanitizeAddress(to);
        ITestCreatorToken1155 token = _deployNewToken(creator);

        vm.assume(tokenOwner != address(token));
        vm.assume(tokenOwner != address(0));
        vm.assume(to != address(0));
        vm.assume(to != address(token));
        vm.assume(tokenId > 0);
        vm.assume(amount > 0);

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

        _mintToken(address(token), tokenOwner, tokenId, amount);

        vm.prank(tokenOwner);
        token.safeTransferFrom(tokenOwner, to, tokenId, amount, "");

        assertEq(token.balanceOf(to, tokenId), amount);
    }

        function testV2IsApprovedForAllDefaultsToFalseForTransferValidator(address creator, address owner) public {
        _sanitizeAddress(creator);
        _sanitizeAddress(owner);
        vm.assume(creator != owner);

        ITestCreatorToken1155 token = _deployNewToken(creator);
        vm.prank(creator);
        token.setTransferValidator(address(validator));

        assertFalse(token.isApprovedForAll(owner, address(validator)));
    }

    function testV2IsApprovedForAllReturnsTrueForTransferValidatorIfAutoApproveEnabledByCreator(address creator, address owner) public {
        _sanitizeAddress(creator);
        _sanitizeAddress(owner);
        vm.assume(creator != owner);

        ITestCreatorToken1155 token = _deployNewToken(creator);
        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        token.setAutomaticApprovalOfTransfersFromValidator(true);
        vm.stopPrank();

        assertTrue(token.isApprovedForAll(owner, address(validator)));
    }

    function testV2IsApprovedForAllReturnsTrueForDefaultTransferValidatorIfAutoApproveEnabledByCreatorAndValidatorUninitialized(address creator, address owner) public {
        _sanitizeAddress(creator);
        _sanitizeAddress(owner);
        vm.assume(creator != owner);

        ITestCreatorToken1155 token = _deployNewToken(creator);
        vm.startPrank(creator);
        token.setAutomaticApprovalOfTransfersFromValidator(true);
        vm.stopPrank();

        assertTrue(token.isApprovedForAll(owner, token.DEFAULT_TRANSFER_VALIDATOR()));
    }

    function testV2IsApprovedForAllReturnsTrueWhenUserExplicitlyApprovesTransferValidator(address creator, address owner) public {
        _sanitizeAddress(creator);
        _sanitizeAddress(owner);
        vm.assume(creator != owner);

        ITestCreatorToken1155 token = _deployNewToken(creator);
        vm.prank(creator);
        token.setTransferValidator(address(validator));

        vm.prank(owner);
        token.setApprovalForAll(address(validator), true);

        assertTrue(token.isApprovedForAll(owner, address(validator)));
    }
}
