// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "./mocks/ContractMock.sol";
import "./mocks/ERC721CMock.sol";
import "./interfaces/ITestCreatorToken.sol";
import "src/utils/TransferPolicy.sol";
import "src/utils/CreatorTokenTransferValidatorV2.sol";

contract CreatorTokenTransferValidatorERC721V2Test is Test {
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

    CreatorTokenTransferValidatorV2 public validator;

    address validatorDeployer;
    address whitelistedOperator;

    function setUp() public virtual {
        validatorDeployer = vm.addr(1);
        vm.startPrank(validatorDeployer);
        validator = new CreatorTokenTransferValidatorV2(validatorDeployer);
        vm.stopPrank();

        whitelistedOperator = vm.addr(2);

        vm.prank(validatorDeployer);
        validator.addOperatorToWhitelist(0, whitelistedOperator);

        console.log(address(validator));
    }

    function _deployNewToken(address creator) internal virtual returns (ITestCreatorToken) {
        vm.prank(creator);
        return ITestCreatorToken(address(new ERC721CMock()));
    }

    function _mintToken(address tokenAddress, address to, uint256 tokenId) internal virtual {
        ERC721CMock(tokenAddress).mint(to, tokenId);
    }

    // function testV2DeterministicAddressForCreatorTokenValidator() public {
    //     assertEq(address(validator), 0xD679fBb2C884Eb28ED08B33e7095caFd63C76e99);
    // }

    function testV2Throwaway() public {

    }

    function testV2TransferSecurityLevelRecommended() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.Recommended);
        assertEq(uint8(TransferSecurityLevels.Recommended), 0);
        assertTrue(callerConstraints == CallerConstraints.OperatorWhitelistEnableOTC);
        assertTrue(receiverConstraints == ReceiverConstraints.None);
    }

    function testV2TransferSecurityLevelZero() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.Zero);
        assertEq(uint8(TransferSecurityLevels.Zero), 1);
        assertTrue(callerConstraints == CallerConstraints.None);
        assertTrue(receiverConstraints == ReceiverConstraints.None);
    }

    function testV2TransferSecurityLevelOne() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.One);
        assertEq(uint8(TransferSecurityLevels.One), 2);
        assertTrue(callerConstraints == CallerConstraints.OperatorBlacklistEnableOTC);
        assertTrue(receiverConstraints == ReceiverConstraints.None);
    }

    function testV2TransferSecurityLevelTwo() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.Two);
        assertEq(uint8(TransferSecurityLevels.Two), 3);
        assertTrue(callerConstraints == CallerConstraints.OperatorWhitelistEnableOTC);
        assertTrue(receiverConstraints == ReceiverConstraints.None);
    }

    function testV2TransferSecurityLevelThree() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.Three);
        assertEq(uint8(TransferSecurityLevels.Three), 4);
        assertTrue(callerConstraints == CallerConstraints.OperatorWhitelistDisableOTC);
        assertTrue(receiverConstraints == ReceiverConstraints.None);
    }

    function testV2TransferSecurityLevelFour() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.Four);
        assertEq(uint8(TransferSecurityLevels.Four), 5);
        assertTrue(callerConstraints == CallerConstraints.OperatorWhitelistEnableOTC);
        assertTrue(receiverConstraints == ReceiverConstraints.NoCode);
    }

    function testV2TransferSecurityLevelFive() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.Five);
        assertEq(uint8(TransferSecurityLevels.Five), 6);
        assertTrue(callerConstraints == CallerConstraints.OperatorWhitelistEnableOTC);
        assertTrue(receiverConstraints == ReceiverConstraints.EOA);
    }

    function testV2TransferSecurityLevelSix() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.Six);
        assertEq(uint8(TransferSecurityLevels.Six), 7);
        assertTrue(callerConstraints == CallerConstraints.OperatorWhitelistDisableOTC);
        assertTrue(receiverConstraints == ReceiverConstraints.NoCode);
    }

    function testV2TransferSecurityLevelSeven() public {
        (CallerConstraints callerConstraints, ReceiverConstraints receiverConstraints) =
            validator.transferSecurityPolicies(TransferSecurityLevels.Seven);
        assertEq(uint8(TransferSecurityLevels.Seven), 8);
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
            CreatorTokenTransferValidatorV2
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

        vm.expectRevert(CreatorTokenTransferValidatorV2.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
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

        vm.expectRevert(CreatorTokenTransferValidatorV2.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
        vm.prank(unauthorizedUser);
        validator.renounceOwnershipOfOperatorWhitelist(listId);
    }

    function testV2GetTransferValidatorReturnsTransferValidatorV2AddressBeforeValidatorIsSet(address creator) public {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);
        assertEq(address(token.getTransferValidator()), token.DEFAULT_TRANSFER_VALIDATOR());
    }

    function testV2RevertsWhenSetTransferValidatorCalledWithContractThatDoesNotImplementRequiredInterface(address creator)
        public
    {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.startPrank(creator);
        address invalidContract = address(new ContractMock());
        vm.expectRevert(CreatorTokenBaseV2.CreatorTokenBase__InvalidTransferValidatorContract.selector);
        token.setTransferValidator(invalidContract);
        vm.stopPrank();
    }

    function testV2AllowsAlternativeValidatorsToBeSetIfTheyImplementRequiredInterface(address creator) public {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.startPrank(creator);
        address alternativeValidator = address(new CreatorTokenTransferValidatorV2(creator));
        token.setTransferValidator(alternativeValidator);
        vm.stopPrank();

        assertEq(address(token.getTransferValidator()), alternativeValidator);
    }

    function testV2AllowsValidatorToBeSetBackToZeroAddress(address creator) public {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.startPrank(creator);
        address alternativeValidator = address(new CreatorTokenTransferValidatorV2(creator));
        token.setTransferValidator(alternativeValidator);
        token.setTransferValidator(address(0));
        vm.stopPrank();

        assertEq(address(token.getTransferValidator()), address(0));
    }

    function testV2GetSecurityPolicyReturnsRecommendedPolicyWhenNoValidatorIsSet(address creator) public {
        vm.assume(creator != address(0));
        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);
        CollectionSecurityPolicy memory securityPolicy = token.getSecurityPolicy();
        assertEq(uint8(securityPolicy.transferSecurityLevel), uint8(TransferSecurityLevels.Recommended));
        assertEq(uint256(securityPolicy.operatorWhitelistId), 0);
        assertEq(uint256(securityPolicy.permittedContractReceiversId), 0);

        CollectionSecurityPolicyV2 memory securityPolicyV2 = token.getSecurityPolicyV2();
        assertEq(uint8(securityPolicyV2.transferSecurityLevel), uint8(TransferSecurityLevels.Recommended));
        assertEq(uint256(securityPolicyV2.listId), 0);
    }

    function testV2GetSecurityPolicyReturnsEmptyPolicyWhenValidatorIsSetToZeroAddress(address creator) public {
        vm.assume(creator != address(0));
        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);

        vm.prank(creator);
        token.setTransferValidator(address(0));

        CollectionSecurityPolicy memory securityPolicy = token.getSecurityPolicy();
        assertEq(uint8(securityPolicy.transferSecurityLevel), uint8(TransferSecurityLevels.Zero));
        assertEq(uint256(securityPolicy.operatorWhitelistId), 0);
        assertEq(uint256(securityPolicy.permittedContractReceiversId), 0);

        CollectionSecurityPolicyV2 memory securityPolicyV2 = token.getSecurityPolicyV2();
        assertEq(uint8(securityPolicyV2.transferSecurityLevel), uint8(TransferSecurityLevels.Zero));
        assertEq(uint256(securityPolicyV2.listId), 0);
    }

    function testV2GetSecurityPolicyReturnsExpectedSecurityPolicy(address creator, uint8 levelUint8) public {
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

        CollectionSecurityPolicy memory securityPolicy = token.getSecurityPolicy();
        assertTrue(securityPolicy.transferSecurityLevel == level);
        assertEq(uint256(securityPolicy.operatorWhitelistId), listId);
        assertEq(uint256(securityPolicy.permittedContractReceiversId), listId);

        CollectionSecurityPolicyV2 memory securityPolicyV2 = token.getSecurityPolicyV2();
        assertTrue(securityPolicyV2.transferSecurityLevel == level);
        assertEq(uint256(securityPolicyV2.listId), listId);
    }

    function testV2SetCustomSecurityPolicy(address creator, uint8 levelUint8) public {
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

        CollectionSecurityPolicy memory securityPolicy = token.getSecurityPolicy();
        assertTrue(securityPolicy.transferSecurityLevel == level);
        assertEq(uint256(securityPolicy.operatorWhitelistId), operatorWhitelistId);
        assertEq(uint256(securityPolicy.permittedContractReceiversId), operatorWhitelistId);

        CollectionSecurityPolicyV2 memory securityPolicyV2 = token.getSecurityPolicyV2();
        assertTrue(securityPolicyV2.transferSecurityLevel == level);
        assertEq(uint256(securityPolicyV2.listId), operatorWhitelistId);
    }

    function testV2SetTransferSecurityLevelOfCollection(address creator, uint8 levelUint8) public {
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

    function testV2SetOperatorWhitelistOfCollection(address creator) public {
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

    function testV2RevertsWhenSettingOperatorWhitelistOfCollectionToInvalidListId(address creator, uint120 listId)
        public
    {
        vm.assume(creator != address(0));
        vm.assume(listId > 1);

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);
        vm.prank(creator);
        vm.expectRevert(CreatorTokenTransferValidatorV2.CreatorTokenTransferValidator__ListDoesNotExist.selector);
        validator.setOperatorWhitelistOfCollection(address(token), listId);
    }

    function testV2RevertsWhenUnauthorizedUserSetsOperatorWhitelistOfCollection(address creator, address unauthorizedUser)
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
            CreatorTokenTransferValidatorV2
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
        ITestCreatorToken token = _deployNewToken(creator);

        vm.startPrank(creator);
        uint120 listId = validator.createOperatorWhitelist("");
        token.setTransferValidator(address(validator));
        validator.setOperatorWhitelistOfCollection(address(token), listId);
        validator.addOperatorToWhitelist(listId, operator1);
        validator.addOperatorToWhitelist(listId, operator2);
        validator.addOperatorToWhitelist(listId, operator3);
        vm.stopPrank();

        assertTrue(token.isOperatorWhitelisted(operator1));
        assertTrue(token.isOperatorWhitelisted(operator2));
        assertTrue(token.isOperatorWhitelisted(operator3));

        address[] memory allowedAddresses = token.getWhitelistedOperators();
        assertEq(allowedAddresses.length, 3);
        assertTrue(allowedAddresses[0] == operator1);
        assertTrue(allowedAddresses[1] == operator2);
        assertTrue(allowedAddresses[2] == operator3);
    }

    function testV2WhitelistedOperatorQueriesWhenUninitializedReturnsDefaultWhitelist(address creator, address operator) public {
        vm.assume(creator != address(0));
        vm.assume(operator != address(0));
        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);
        assertFalse(token.isOperatorWhitelisted(operator));
        address[] memory allowedAddresses = token.getWhitelistedOperators();
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

        assertTrue(token.isContractReceiverPermitted(receiver1));
        assertTrue(token.isContractReceiverPermitted(receiver2));
        assertTrue(token.isContractReceiverPermitted(receiver3));

        address[] memory allowedAddresses = token.getPermittedContractReceivers();
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
        ITestCreatorToken token = _deployNewToken(creator);
        assertFalse(token.isContractReceiverPermitted(receiver));
        address[] memory allowedAddresses = token.getPermittedContractReceivers();
        assertEq(allowedAddresses.length, 1);
        assertEq(allowedAddresses[0], whitelistedOperator);
    }

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
        ITestCreatorToken token = _deployNewToken(creator);
        assertFalse(token.isTransferAllowed(caller, from, to));
    }

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
        ITestCreatorToken token = _deployNewToken(creator);
        
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

        vm.expectRevert(CreatorTokenTransferValidatorV2.CreatorTokenTransferValidator__CallerDoesNotOwnList.selector);
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

    function testV2PolicyLevelZeroPermitsAllTransfers(address creator, address caller, address from, address to) public {
        vm.assume(creator != address(0));
        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);
        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        validator.setTransferSecurityLevelOfCollection(address(token), TransferSecurityLevels.Zero);
        vm.stopPrank();
        assertTrue(token.isTransferAllowed(caller, from, to));
    }

    function testV2WhitelistPoliciesWithOTCEnabledBlockTransfersWhenCallerNotWhitelistedOrOwner(
        address creator,
        address caller,
        address from,
        uint160 toKey
    ) public {
        _sanitizeAddress(caller);
        _sanitizeAddress(from);
        address to = _verifyEOA(toKey);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Recommended, creator, caller, from, to);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Two, creator, caller, from, to);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Four, creator, caller, from, to);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Five, creator, caller, from, to);
    }

    function testV2WhitelistPoliciesWithOTCEnabledAllowTransfersWhenCalledByOwner(
        address creator,
        address tokenOwner,
        uint160 toKey
    ) public {
        address to = _verifyEOA(toKey);
        _testPolicyAllowsTransfersWhenCalledByOwner(TransferSecurityLevels.Recommended, creator, tokenOwner, to);
        _testPolicyAllowsTransfersWhenCalledByOwner(TransferSecurityLevels.Two, creator, tokenOwner, to);
        _testPolicyAllowsTransfersWhenCalledByOwner(TransferSecurityLevels.Four, creator, tokenOwner, to);
        _testPolicyAllowsTransfersWhenCalledByOwner(TransferSecurityLevels.Five, creator, tokenOwner, to);
    }

    function testV2WhitelistPoliciesWithOTCDisabledBlockTransfersWhenCallerNotWhitelistedOrOwner(
        address creator,
        address caller,
        address from,
        uint160 toKey
    ) public {
        address to = _verifyEOA(toKey);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Three, creator, caller, from, to);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Six, creator, caller, from, to);
        _testPolicyBlocksTransfersWhenCallerNotWhitelistedOrOwner(TransferSecurityLevels.Seven, creator, caller, from, to);
    }

    function testV2WhitelistPoliciesWithOTCDisabledBlockTransfersWhenCalledByOwner(
        address creator,
        address tokenOwner,
        uint160 toKey
    ) public {
        address to = _verifyEOA(toKey);
        _testPolicyBlocksTransfersWhenCalledByOwner(TransferSecurityLevels.Three, creator, tokenOwner, to);
        _testPolicyBlocksTransfersWhenCalledByOwner(TransferSecurityLevels.Six, creator, tokenOwner, to);
        _testPolicyBlocksTransfersWhenCalledByOwner(TransferSecurityLevels.Seven, creator, tokenOwner, to);
    }

    function testV2NoCodePoliciesBlockTransferWhenDestinationIsAContract(address creator, address caller, address from)
        public
    {
        _sanitizeAddress(caller);
        _sanitizeAddress(from);
        _testPolicyBlocksTransfersToContractReceivers(TransferSecurityLevels.Four, creator, caller, from);
        _testPolicyBlocksTransfersToContractReceivers(TransferSecurityLevels.Six, creator, caller, from);
    }

    function testV2NoCodePoliciesAllowTransferToPermittedContractDestinations(
        address creator,
        address caller,
        address from
    ) public {
        _testPolicyAllowsTransfersToPermittedContractReceivers(TransferSecurityLevels.Three, creator, caller, from);
        _testPolicyAllowsTransfersToPermittedContractReceivers(TransferSecurityLevels.Five, creator, caller, from);
    }

    function testV2EOAPoliciesBlockTransferWhenDestinationHasNotVerifiedSignature(
        address creator,
        address caller,
        address from,
        address to
    ) public {
        _testPolicyBlocksTransfersToWalletsThatHaveNotVerifiedEOASignature(
            TransferSecurityLevels.Five, creator, caller, from, to
        );
        _testPolicyBlocksTransfersToWalletsThatHaveNotVerifiedEOASignature(
            TransferSecurityLevels.Seven, creator, caller, from, to
        );
    }

    function testV2EOAPoliciesAllowTransferWhenDestinationHasVerifiedSignature(
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

    function testV2EOAPoliciesAllowTransferToPermittedContractDestinations(address creator, address caller, address from)
        public
    {
        _sanitizeAddress(caller);
        _sanitizeAddress(creator);
        _sanitizeAddress(from);
        _testPolicyAllowsTransfersToPermittedContractReceivers(TransferSecurityLevels.Five, creator, caller, from);
        _testPolicyAllowsTransfersToPermittedContractReceivers(TransferSecurityLevels.Seven, creator, caller, from);
    }

    function testV2WhitelistPoliciesAllowAllTransfersWhenOperatorWhitelistIsEmpty(
        address creator,
        address caller,
        address from,
        uint160 toKey
    ) public {
        address to = _verifyEOA(toKey);
        _testPolicyAllowsAllTransfersWhenOperatorWhitelistIsEmpty(TransferSecurityLevels.Two, creator, caller, from, to);
        _testPolicyAllowsAllTransfersWhenOperatorWhitelistIsEmpty(TransferSecurityLevels.Three, creator, caller, from, to);
        _testPolicyAllowsAllTransfersWhenOperatorWhitelistIsEmpty(TransferSecurityLevels.Four, creator, caller, from, to);
        _testPolicyAllowsAllTransfersWhenOperatorWhitelistIsEmpty(TransferSecurityLevels.Five, creator, caller, from, to);
        _testPolicyAllowsAllTransfersWhenOperatorWhitelistIsEmpty(TransferSecurityLevels.Six, creator, caller, from, to);
        _testPolicyAllowsAllTransfersWhenOperatorWhitelistIsEmpty(TransferSecurityLevels.Seven, creator, caller, from, to);
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
            CreatorTokenTransferValidatorV2.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector
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
            CreatorTokenTransferValidatorV2.CreatorTokenTransferValidator__CallerMustBeWhitelisted.selector
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
            CreatorTokenTransferValidatorV2.CreatorTokenTransferValidator__ReceiverMustNotHaveDeployedCode.selector
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
            CreatorTokenTransferValidatorV2.CreatorTokenTransferValidator__ReceiverProofOfEOASignatureUnverified.selector
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
}
