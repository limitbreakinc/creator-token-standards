// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../mocks/ERC721Mock.sol";
import "../mocks/ERC721CWMock.sol";
import "../mocks/ClonerMock.sol";
import "../CreatorTokenNonfungible.t.sol";

contract ERC721CWTest is CreatorTokenNonfungibleTest {
    event Staked(uint256 indexed tokenId, address indexed account);
    event Unstaked(uint256 indexed tokenId, address indexed account);
    event StakerConstraintsSet(StakerConstraints stakerConstraints);

    ERC721Mock public wrappedTokenMock;
    ERC721CWMock public tokenMock;

    function setUp() public virtual override {
        super.setUp();

        wrappedTokenMock = new ERC721Mock();
        tokenMock = new ERC721CWMock(address(wrappedTokenMock));
        //TODO: tokenMock.setToCustomValidatorAndSecurityPolicy(address(validator), TransferSecurityLevels.Two, 0);
    }

    function _deployNewToken(address creator) internal virtual override returns (ITestCreatorToken) {
        vm.startPrank(creator);
        address wrappedToken = address(new ERC721Mock());
        ITestCreatorToken token = ITestCreatorToken(address(new ERC721CWMock(wrappedToken)));
        vm.stopPrank();
        return token;
    }

    function testRevertsWhenDeployingWithZeroAddressWrapper() public {
        address wrappedToken = address(0);

        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__InvalidERC721Collection.selector);
        ERC721CWMock newMock = new ERC721CWMock(wrappedToken);
    }

    function testRevertsWhenDeployingWithZeroCodeLengthWrapper() public {
        address wrappedToken = address(uint160(uint256(keccak256(abi.encode(0)))));

        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__InvalidERC721Collection.selector);
        ERC721CWMock newMock = new ERC721CWMock(wrappedToken);
    }

    function _mintToken(address tokenAddress, address to, uint256 tokenId) internal virtual override {
        address wrappedTokenAddress = ERC721CWMock(tokenAddress).getWrappedCollectionAddress();
        vm.startPrank(to);
        ERC721Mock(wrappedTokenAddress).mint(to, tokenId);
        ERC721Mock(wrappedTokenAddress).setApprovalForAll(tokenAddress, true);
        ERC721CWMock(tokenAddress).mint(to, tokenId);
        vm.stopPrank();
    }

    function testSupportedTokenInterfaces() public {
        assertEq(tokenMock.supportsInterface(type(ICreatorToken).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(ICreatorTokenWrapperERC721).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC721).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC721Metadata).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC165).interfaceId), true);
    }

    function testGetTransferValidationFunction() public override {
        (bytes4 functionSignature, bool isViewFunction) = tokenMock.getTransferValidationFunction();

        assertEq(functionSignature, bytes4(keccak256("validateTransfer(address,address,address,uint256)")));
        assertEq(isViewFunction, true);
    }

    function testWrappedCollectionAddress() public {
        assertEq(tokenMock.getWrappedCollectionAddress(), address(wrappedTokenMock));
    }

    function testRevertsWhenWrappingZeroAddress() public {
        vm.expectRevert();
        new ERC721CWMock(address(0));
    }

    function testRevertsWhenWrappingNoCode(address noCodeToken) public {
        vm.assume(noCodeToken.code.length == 0);
        vm.expectRevert();
        new ERC721CWMock(noCodeToken);
    }

    function testCanUnstakeReturnsFalseWhenTokensDoNotExist(uint256 tokenId) public {
        assertFalse(tokenMock.canUnstake(tokenId));
    }

    function testCanUnstakeReturnsTrueForStakedTokenIds(address to, uint256 tokenId) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        _mintToken(address(tokenMock), to, tokenId);
        assertTrue(tokenMock.canUnstake(tokenId));
    }

    function testWrappedCollectionHoldersCanStakeTokens(address to, uint256 tokenId) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stake(tokenId);
        vm.stopPrank();

        assertEq(tokenMock.ownerOf(tokenId), to);
        assertEq(wrappedTokenMock.ownerOf(tokenId), address(tokenMock));
    }

    function testStakeToWrappedCollectionHoldersCanStakeTokens(address to, uint256 tokenId, address stakeReceiver) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        assertEq(tokenMock.ownerOf(tokenId), stakeReceiver);
        assertEq(wrappedTokenMock.ownerOf(tokenId), address(tokenMock));
    }

    function testRevertsWhenNativeFundsIncludedInStake(address to, uint256 tokenId, uint256 value) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(value > 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.deal(to, value);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__DefaultImplementationOfStakeDoesNotAcceptPayment.selector);
        tokenMock.stake{value: value}(tokenId);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenNativeFundsIncludedInStake(address to, uint256 tokenId, uint256 value, address stakeReceiver) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(value > 0);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.deal(to, value);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__DefaultImplementationOfStakeDoesNotAcceptPayment.selector);
        tokenMock.stakeTo{value: value}(tokenId, stakeReceiver);
        vm.stopPrank();
    }

    function testRevertsWhenUnauthorizedUserAttemptsToStake(address to, address unauthorizedUser, uint256 tokenId)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        vm.startPrank(unauthorizedUser);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerNotOwnerOfWrappedToken.selector);
        tokenMock.stake(tokenId);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenUnauthorizedUserAttemptsToStake(address to, address unauthorizedUser, uint256 tokenId, address stakeReceiver)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        vm.startPrank(unauthorizedUser);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerNotOwnerOfWrappedToken.selector);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();
    }

    function testRevertsWhenApprovedOperatorAttemptsToStake(address to, address approvedOperator, uint256 tokenId)
        public
    {
        vm.assume(to != address(0));
        vm.assume(approvedOperator != address(0));
        vm.assume(to != approvedOperator);
        vm.assume(to != address(tokenMock));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        wrappedTokenMock.setApprovalForAll(approvedOperator, true);
        vm.stopPrank();

        vm.startPrank(approvedOperator);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerNotOwnerOfWrappedToken.selector);
        tokenMock.stake(tokenId);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenApprovedOperatorAttemptsToStake(address to, address approvedOperator, uint256 tokenId, address stakeReceiver)
        public
    {
        vm.assume(to != address(0));
        vm.assume(approvedOperator != address(0));
        vm.assume(to != approvedOperator);
        vm.assume(to != address(tokenMock));
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        wrappedTokenMock.setApprovalForAll(approvedOperator, true);
        vm.stopPrank();

        vm.startPrank(approvedOperator);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerNotOwnerOfWrappedToken.selector);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();
    }

    function testRevertsWhenUnauthorizedUserAttemptsToUnstake(address to, address unauthorizedUser, uint256 tokenId)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stake(tokenId);
        vm.stopPrank();

        vm.startPrank(unauthorizedUser);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerNotOwnerOfWrappingToken.selector);
        tokenMock.unstake(tokenId);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenUnauthorizedUserAttemptsToUnstake(address to, address unauthorizedUser, uint256 tokenId, address stakeReceiver)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));
        _sanitizeAddress(stakeReceiver);
        vm.assume(stakeReceiver != unauthorizedUser);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        vm.startPrank(unauthorizedUser);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerNotOwnerOfWrappingToken.selector);
        tokenMock.unstake(tokenId);
        vm.stopPrank();
    }

    function testRevertsWhenApprovedOperatorAttemptsToUnstake(address to, address approvedOperator, uint256 tokenId)
        public
    {
        vm.assume(to != address(0));
        vm.assume(approvedOperator != address(0));
        vm.assume(to != approvedOperator);
        vm.assume(to != address(tokenMock));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        wrappedTokenMock.setApprovalForAll(approvedOperator, true);
        tokenMock.setApprovalForAll(approvedOperator, true);
        tokenMock.stake(tokenId);
        vm.stopPrank();

        vm.startPrank(approvedOperator);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerNotOwnerOfWrappingToken.selector);
        tokenMock.unstake(tokenId);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenApprovedOperatorAttemptsToUnstake(address to, address approvedOperator, uint256 tokenId, address stakeReceiver)
        public
    {
        vm.assume(to != address(0));
        vm.assume(approvedOperator != address(0));
        vm.assume(to != approvedOperator);
        vm.assume(to != address(tokenMock));
        _sanitizeAddress(stakeReceiver);
        vm.assume(stakeReceiver != approvedOperator);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        wrappedTokenMock.setApprovalForAll(approvedOperator, true);
        tokenMock.setApprovalForAll(approvedOperator, true);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        vm.prank(stakeReceiver);
        tokenMock.setApprovalForAll(approvedOperator, true);

        vm.startPrank(approvedOperator);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerNotOwnerOfWrappingToken.selector);
        tokenMock.unstake(tokenId);
        vm.stopPrank();
    }

    function testRevertsWhenUserAttemptsToUnstakeATokenThatHasNotBeenStaked(address to, uint256 tokenId) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.expectRevert("ERC721: invalid token ID");
        tokenMock.unstake(tokenId);
        vm.stopPrank();
    }

    function testWrappingCollectionHoldersCanUnstakeTokens(address to, uint256 tokenId) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stake(tokenId);
        tokenMock.unstake(tokenId);
        vm.stopPrank();

        vm.expectRevert("ERC721: invalid token ID");
        address ownerOfWrapper = tokenMock.ownerOf(tokenId);
        assertEq(wrappedTokenMock.ownerOf(tokenId), to);
    }

    function testStakeToWrappingCollectionHoldersCanUnstakeTokens(address to, uint256 tokenId, address stakeReceiver) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        vm.prank(stakeReceiver);
        tokenMock.unstake(tokenId);

        vm.expectRevert("ERC721: invalid token ID");
        address ownerOfWrapper = tokenMock.ownerOf(tokenId);
        assertEq(wrappedTokenMock.ownerOf(tokenId), stakeReceiver);
    }

    function testRevertsWhenNativeFundsIncludedInUnstakeCall(address to, uint256 tokenId, uint256 value) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(value > 0);

        vm.deal(to, value);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stake(tokenId);
        vm.expectRevert(
            ERC721WrapperBase.ERC721WrapperBase__DefaultImplementationOfUnstakeDoesNotAcceptPayment.selector
        );
        tokenMock.unstake{value: value}(tokenId);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenNativeFundsIncludedInUnstakeCall(address to, uint256 tokenId, uint256 value, address stakeReceiver) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(value > 0);
        _sanitizeAddress(stakeReceiver);

        vm.deal(stakeReceiver, value);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        vm.prank(stakeReceiver);
        vm.expectRevert(
            ERC721WrapperBase.ERC721WrapperBase__DefaultImplementationOfUnstakeDoesNotAcceptPayment.selector
        );
        tokenMock.unstake{value: value}(tokenId);
    }

    function testSecondaryWrappingCollectionHoldersCanUnstakeTokens(
        address to,
        address secondaryHolder,
        uint256 tokenId
    ) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(secondaryHolder != address(0));
        vm.assume(secondaryHolder != address(tokenMock));
        vm.assume(to != secondaryHolder);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stake(tokenId);
        tokenMock.transferFrom(to, secondaryHolder, tokenId);
        vm.stopPrank();

        vm.startPrank(secondaryHolder);
        tokenMock.unstake(tokenId);
        vm.stopPrank();

        vm.expectRevert("ERC721: invalid token ID");
        address ownerOfWrapper = tokenMock.ownerOf(tokenId);
        assertEq(wrappedTokenMock.ownerOf(tokenId), secondaryHolder);
    }

    function testStakeToSecondaryWrappingCollectionHoldersCanUnstakeTokens(
        address to,
        address secondaryHolder,
        uint256 tokenId,
        address stakeReceiver
    ) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(secondaryHolder != address(0));
        vm.assume(secondaryHolder != address(tokenMock));
        vm.assume(to != secondaryHolder);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        vm.startPrank(stakeReceiver);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.transferFrom(stakeReceiver, secondaryHolder, tokenId);
        vm.stopPrank();

        vm.startPrank(secondaryHolder);
        tokenMock.unstake(tokenId);
        vm.stopPrank();

        vm.expectRevert("ERC721: invalid token ID");
        address ownerOfWrapper = tokenMock.ownerOf(tokenId);
        assertEq(wrappedTokenMock.ownerOf(tokenId), secondaryHolder);
    }

    function testCanSetStakerConstraints(uint8 constraintsUint8) public {
        vm.assume(constraintsUint8 <= 2);
        StakerConstraints constraints = StakerConstraints(constraintsUint8);

        vm.expectEmit(false, false, false, true);
        emit StakerConstraintsSet(constraints);
        tokenMock.setStakerConstraints(constraints);
        assertEq(uint8(tokenMock.getStakerConstraints()), uint8(constraints));
    }

    function testRevertsWhenUnauthorizedUserAttemptsToSetStakerConstraints(
        address unauthorizedUser,
        uint8 constraintsUint8
    ) public {
        vm.assume(unauthorizedUser != address(0));
        vm.assume(unauthorizedUser != address(tokenMock));
        vm.assume(unauthorizedUser != address(this));
        vm.assume(constraintsUint8 <= 2);
        StakerConstraints constraints = StakerConstraints(constraintsUint8);

        vm.prank(unauthorizedUser);
        vm.expectRevert("Ownable: caller is not the owner");
        tokenMock.setStakerConstraints(constraints);
    }

    function testEOACanStakeTokensWhenStakerConstraintsAreInEffect(address to, uint256 tokenId) public {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(to.code.length == 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.CallerIsTxOrigin);

        vm.startPrank(to, to);
        tokenMock.stake(tokenId);
        vm.stopPrank();

        assertEq(tokenMock.ownerOf(tokenId), to);
        assertEq(wrappedTokenMock.ownerOf(tokenId), address(tokenMock));
    }

    function testStakeToEOACanStakeTokensWhenStakerConstraintsAreInEffect(address to, uint256 tokenId, address stakeReceiver) public {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(to.code.length == 0);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.CallerIsTxOrigin);

        vm.startPrank(to, stakeReceiver);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        assertEq(tokenMock.ownerOf(tokenId), stakeReceiver);
        assertEq(wrappedTokenMock.ownerOf(tokenId), address(tokenMock));
    }

    function testEOACanStakeTokensWhenEOAStakerConstraintsAreInEffectButValidatorIsUnset(address to, uint256 tokenId)
        public
    {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(to.code.length == 0);

        tokenMock.setTransferValidator(address(0));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.startPrank(to, to);
        tokenMock.stake(tokenId);
        vm.stopPrank();

        assertEq(tokenMock.ownerOf(tokenId), to);
        assertEq(wrappedTokenMock.ownerOf(tokenId), address(tokenMock));
    }

    function testStakeToEOACanStakeTokensWhenEOAStakerConstraintsAreInEffectButValidatorIsUnset(address to, uint256 tokenId, address stakeReceiver)
        public
    {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(to.code.length == 0);
        _sanitizeAddress(stakeReceiver);

        tokenMock.setTransferValidator(address(0));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.startPrank(to, stakeReceiver);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        assertEq(tokenMock.ownerOf(tokenId), stakeReceiver);
        assertEq(wrappedTokenMock.ownerOf(tokenId), address(tokenMock));
    }

    function testVerifiedEOACanStakeTokensWhenEOAStakerConstraintsAreInEffect(uint160 toKey, uint256 tokenId) public {
        address to = _verifyEOA(toKey);
        _sanitizeAddress(to);
        vm.assume(to != address(0));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.startPrank(to);
        tokenMock.stake(tokenId);
        vm.stopPrank();

        assertEq(tokenMock.ownerOf(tokenId), to);
        assertEq(wrappedTokenMock.ownerOf(tokenId), address(tokenMock));
    }

    function testStakeToVerifiedEOACanStakeTokensWhenEOAStakerConstraintsAreInEffect(uint160 toKey, uint256 tokenId, uint160 stakeReceiverKey) public {
        vm.assume(toKey != stakeReceiverKey);

        address to = _verifyEOA(toKey);
        address stakeReceiver = _verifyEOA(stakeReceiverKey);
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.startPrank(to);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        assertEq(tokenMock.ownerOf(tokenId), stakeReceiver);
        assertEq(wrappedTokenMock.ownerOf(tokenId), address(tokenMock));
    }

    function testRevertsWhenCallerIsTxOriginConstraintIsInEffectIfCallerIsNotOrigin(
        address to,
        address origin,
        uint256 tokenId
    ) public {
        _sanitizeAddress(to);
        _sanitizeAddress(origin);
        vm.assume(to != address(0));
        vm.assume(origin != address(0));
        vm.assume(to != origin);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.CallerIsTxOrigin);

        vm.prank(to, origin);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__SmartContractsNotPermittedToStake.selector);
        tokenMock.stake(tokenId);
    }

    function testStakeToRevertsWhenCallerIsTxOriginConstraintIsInEffectIfCallerIsNotOrigin(
        address to,
        address origin,
        uint256 tokenId,
        address stakeReceiver
    ) public {
        _sanitizeAddress(to);
        _sanitizeAddress(origin);
        vm.assume(to != address(0));
        vm.assume(origin != address(0));
        vm.assume(to != origin);
        _sanitizeAddress(stakeReceiver);
        vm.assume(stakeReceiver != to);
        vm.assume(stakeReceiver != origin);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.CallerIsTxOrigin);

        vm.prank(to, origin);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__SmartContractsNotPermittedToStake.selector);
        tokenMock.stakeTo(tokenId, stakeReceiver);
    }

    function testRevertsWhenCallerIsEOAConstraintIsInEffectIfCallerHasNotVerifiedSignature(address to, uint256 tokenId)
        public
    {
        _sanitizeAddress(to);
        vm.assume(to != address(0));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.prank(to);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerSignatureNotVerifiedInEOARegistry.selector);
        tokenMock.stake(tokenId);
    }

    function testStakeToRevertsWhenCallerIsEOAConstraintIsInEffectIfCallerHasNotVerifiedSignature(address to, uint256 tokenId, address stakeReceiver)
        public
    {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.prank(to);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerSignatureNotVerifiedInEOARegistry.selector);
        tokenMock.stakeTo(tokenId, stakeReceiver);
    }

    function _sanitizeAddress(address addr) internal view virtual override {
        super._sanitizeAddress(addr);
        vm.assume(addr != address(tokenMock));
        vm.assume(addr != address(wrappedTokenMock));
    }
}

contract ERC721CWInitializableTest is CreatorTokenNonfungibleTest {
    event Staked(uint256 indexed tokenId, address indexed account);
    event Unstaked(uint256 indexed tokenId, address indexed account);
    event StakerConstraintsSet(StakerConstraints stakerConstraints);

    ClonerMock cloner;

    ERC721Mock wrappedTokenMock;

    ERC721CWInitializableMock public referenceTokenMock;
    ERC721CWInitializableMock public tokenMock;

    function setUp() public virtual override {
        super.setUp();

        cloner = new ClonerMock();

        wrappedTokenMock = new ERC721Mock();

        referenceTokenMock = new ERC721CWInitializableMock();

        bytes4[] memory initializationSelectors = new bytes4[](1);
        bytes[] memory initializationArguments = new bytes[](1);

        initializationSelectors[0] = referenceTokenMock.initializeWrappedCollectionAddress.selector;
        initializationArguments[0] = abi.encode(address(wrappedTokenMock));

        tokenMock = ERC721CWInitializableMock(
            cloner.cloneContract(
                address(referenceTokenMock), address(this), initializationSelectors, initializationArguments
            )
        );

        //TODO: tokenMock.setToCustomValidatorAndSecurityPolicy(address(validator), TransferSecurityLevels.Two, 0);
    }

    function _deployNewToken(address creator) internal virtual override returns (ITestCreatorToken) {
        vm.startPrank(creator);
        address wrappedToken = address(new ERC721Mock());

        bytes4[] memory initializationSelectors = new bytes4[](1);
        bytes[] memory initializationArguments = new bytes[](1);

        initializationSelectors[0] = referenceTokenMock.initializeWrappedCollectionAddress.selector;
        initializationArguments[0] = abi.encode(address(wrappedToken));

        ITestCreatorToken token = ITestCreatorToken(
            cloner.cloneContract(address(referenceTokenMock), creator, initializationSelectors, initializationArguments)
        );
        vm.stopPrank();
        return token;
    }

    function testRevertsWhenDeployingInitializableWithZeroAddressWrapper() public {
        address wrappedToken = address(0);

        bytes4[] memory initializationSelectors = new bytes4[](1);
        bytes[] memory initializationArguments = new bytes[](1);

        initializationSelectors[0] = referenceTokenMock.initializeWrappedCollectionAddress.selector;
        initializationArguments[0] = abi.encode(address(wrappedToken));

        vm.expectRevert(abi.encodePacked(ClonerMock.InitializationArgumentInvalid.selector, uint256(0)));
        cloner.cloneContract(address(referenceTokenMock), address(this), initializationSelectors, initializationArguments);
    }

    function testRevertsWhenDeployingInitializableWithZeroCodeLengthWrapper() public {
        address wrappedToken = address(uint160(uint256(keccak256(abi.encode(0)))));

        bytes4[] memory initializationSelectors = new bytes4[](1);
        bytes[] memory initializationArguments = new bytes[](1);

        initializationSelectors[0] = referenceTokenMock.initializeWrappedCollectionAddress.selector;
        initializationArguments[0] = abi.encode(address(wrappedToken));

        vm.expectRevert(abi.encodePacked(ClonerMock.InitializationArgumentInvalid.selector, uint256(0)));
        cloner.cloneContract(address(referenceTokenMock), address(this), initializationSelectors, initializationArguments);
    }

    function _mintToken(address tokenAddress, address to, uint256 tokenId) internal virtual override {
        address wrappedTokenAddress = ERC721CWInitializableMock(tokenAddress).getWrappedCollectionAddress();
        vm.startPrank(to);
        ERC721Mock(wrappedTokenAddress).mint(to, tokenId);
        ERC721Mock(wrappedTokenAddress).setApprovalForAll(tokenAddress, true);
        ERC721CWInitializableMock(tokenAddress).mint(to, tokenId);
        vm.stopPrank();
    }

    function testSupportedTokenInterfaces() public {
        assertEq(tokenMock.supportsInterface(type(ICreatorToken).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(ICreatorTokenWrapperERC721).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC721).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC721Metadata).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC165).interfaceId), true);
    }

    function testGetTransferValidationFunction() public override {
        (bytes4 functionSignature, bool isViewFunction) = tokenMock.getTransferValidationFunction();

        assertEq(functionSignature, bytes4(keccak256("validateTransfer(address,address,address,uint256)")));
        assertEq(isViewFunction, true);
    }

    function testInitializeAlreadyInitialized(address badAddress) public {
        vm.expectRevert(ERC721CWInitializable.ERC721CWInitializable__AlreadyInitializedWrappedCollection.selector);
        tokenMock.initializeWrappedCollectionAddress(badAddress);
    }

    function testRevertsWhenInitializingOwnerAgain(address badOwner) public {
        vm.expectRevert(OwnableInitializable.InitializableOwnable__OwnerAlreadyInitialized.selector);
        tokenMock.initializeOwner(badOwner);
    }

    function testCanUnstakeReturnsFalseWhenTokensDoNotExist(uint256 tokenId) public {
        assertFalse(tokenMock.canUnstake(tokenId));
    }

    function testCanUnstakeReturnsTrueForStakedTokenIds(address to, uint256 tokenId) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        _mintToken(address(tokenMock), to, tokenId);
        assertTrue(tokenMock.canUnstake(tokenId));
    }

    function testWrappedCollectionHoldersCanStakeTokens(address to, uint256 tokenId) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stake(tokenId);
        vm.stopPrank();

        assertEq(tokenMock.ownerOf(tokenId), to);
        assertEq(wrappedTokenMock.ownerOf(tokenId), address(tokenMock));
    }

    function testStakeToWrappedCollectionHoldersCanStakeTokens(address to, uint256 tokenId, address stakeReceiver) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        assertEq(tokenMock.ownerOf(tokenId), stakeReceiver);
        assertEq(wrappedTokenMock.ownerOf(tokenId), address(tokenMock));
    }

    function testRevertsWhenNativeFundsIncludedInStake(address to, uint256 tokenId, uint256 value) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(value > 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.deal(to, value);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__DefaultImplementationOfStakeDoesNotAcceptPayment.selector);
        tokenMock.stake{value: value}(tokenId);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenNativeFundsIncludedInStake(address to, uint256 tokenId, uint256 value, address stakeReceiver) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(value > 0);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.deal(to, value);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__DefaultImplementationOfStakeDoesNotAcceptPayment.selector);
        tokenMock.stakeTo{value: value}(tokenId, stakeReceiver);
        vm.stopPrank();
    }

    function testRevertsWhenUnauthorizedUserAttemptsToStake(address to, address unauthorizedUser, uint256 tokenId)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        vm.startPrank(unauthorizedUser);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerNotOwnerOfWrappedToken.selector);
        tokenMock.stake(tokenId);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenUnauthorizedUserAttemptsToStake(address to, address unauthorizedUser, uint256 tokenId, address stakeReceiver)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        vm.startPrank(unauthorizedUser);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerNotOwnerOfWrappedToken.selector);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();
    }

    function testRevertsWhenApprovedOperatorAttemptsToStake(address to, address approvedOperator, uint256 tokenId)
        public
    {
        vm.assume(to != address(0));
        vm.assume(approvedOperator != address(0));
        vm.assume(to != approvedOperator);
        vm.assume(to != address(tokenMock));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        wrappedTokenMock.setApprovalForAll(approvedOperator, true);
        vm.stopPrank();

        vm.startPrank(approvedOperator);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerNotOwnerOfWrappedToken.selector);
        tokenMock.stake(tokenId);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenApprovedOperatorAttemptsToStake(address to, address approvedOperator, uint256 tokenId, address stakeReceiver)
        public
    {
        vm.assume(to != address(0));
        vm.assume(approvedOperator != address(0));
        vm.assume(to != approvedOperator);
        vm.assume(to != address(tokenMock));
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        wrappedTokenMock.setApprovalForAll(approvedOperator, true);
        vm.stopPrank();

        vm.startPrank(approvedOperator);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerNotOwnerOfWrappedToken.selector);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();
    }

    function testRevertsWhenUnauthorizedUserAttemptsToUnstake(address to, address unauthorizedUser, uint256 tokenId)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stake(tokenId);
        vm.stopPrank();

        vm.startPrank(unauthorizedUser);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerNotOwnerOfWrappingToken.selector);
        tokenMock.unstake(tokenId);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenUnauthorizedUserAttemptsToUnstake(address to, address unauthorizedUser, uint256 tokenId, address stakeReceiver)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));
        _sanitizeAddress(stakeReceiver);
        vm.assume(stakeReceiver != unauthorizedUser);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        vm.startPrank(unauthorizedUser);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerNotOwnerOfWrappingToken.selector);
        tokenMock.unstake(tokenId);
        vm.stopPrank();
    }

    function testRevertsWhenApprovedOperatorAttemptsToUnstake(address to, address approvedOperator, uint256 tokenId)
        public
    {
        vm.assume(to != address(0));
        vm.assume(approvedOperator != address(0));
        vm.assume(to != approvedOperator);
        vm.assume(to != address(tokenMock));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        wrappedTokenMock.setApprovalForAll(approvedOperator, true);
        tokenMock.setApprovalForAll(approvedOperator, true);
        tokenMock.stake(tokenId);
        vm.stopPrank();

        vm.startPrank(approvedOperator);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerNotOwnerOfWrappingToken.selector);
        tokenMock.unstake(tokenId);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenApprovedOperatorAttemptsToUnstake(address to, address approvedOperator, uint256 tokenId, address stakeReceiver)
        public
    {
        vm.assume(to != address(0));
        vm.assume(approvedOperator != address(0));
        vm.assume(to != approvedOperator);
        vm.assume(to != address(tokenMock));
        _sanitizeAddress(stakeReceiver);
        vm.assume(stakeReceiver != approvedOperator);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        wrappedTokenMock.setApprovalForAll(approvedOperator, true);
        tokenMock.setApprovalForAll(approvedOperator, true);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        vm.startPrank(stakeReceiver);
        tokenMock.setApprovalForAll(approvedOperator, true);
        vm.stopPrank();

        vm.startPrank(approvedOperator);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerNotOwnerOfWrappingToken.selector);
        tokenMock.unstake(tokenId);
        vm.stopPrank();
    }

    function testRevertsWhenUserAttemptsToUnstakeATokenThatHasNotBeenStaked(address to, uint256 tokenId) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.expectRevert("ERC721: invalid token ID");
        tokenMock.unstake(tokenId);
        vm.stopPrank();
    }

    function testWrappingCollectionHoldersCanUnstakeTokens(address to, uint256 tokenId) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stake(tokenId);
        tokenMock.unstake(tokenId);
        vm.stopPrank();

        vm.expectRevert("ERC721: invalid token ID");
        address ownerOfWrapper = tokenMock.ownerOf(tokenId);
        assertEq(wrappedTokenMock.ownerOf(tokenId), to);
    }

    function testStakeToWrappingCollectionHoldersCanUnstakeTokens(address to, uint256 tokenId, address stakeReceiver) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        vm.startPrank(stakeReceiver);
        tokenMock.unstake(tokenId);
        vm.stopPrank();

        vm.expectRevert("ERC721: invalid token ID");
        address ownerOfWrapper = tokenMock.ownerOf(tokenId);
        assertEq(wrappedTokenMock.ownerOf(tokenId), stakeReceiver);
    }

    function testRevertsWhenNativeFundsIncludedInUnstakeCall(address to, uint256 tokenId, uint256 value) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(value > 0);

        vm.deal(to, value);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stake(tokenId);
        vm.expectRevert(
            ERC721WrapperBase.ERC721WrapperBase__DefaultImplementationOfUnstakeDoesNotAcceptPayment.selector
        );
        tokenMock.unstake{value: value}(tokenId);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenNativeFundsIncludedInUnstakeCall(address to, uint256 tokenId, uint256 value, address stakeReceiver) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(value > 0);
        _sanitizeAddress(stakeReceiver);

        vm.deal(stakeReceiver, value);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        vm.startPrank(stakeReceiver);
        vm.expectRevert(
            ERC721WrapperBase.ERC721WrapperBase__DefaultImplementationOfUnstakeDoesNotAcceptPayment.selector
        );
        tokenMock.unstake{value: value}(tokenId);
        vm.stopPrank();
    }

    function testSecondaryWrappingCollectionHoldersCanUnstakeTokens(
        address to,
        address secondaryHolder,
        uint256 tokenId
    ) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(secondaryHolder != address(0));
        vm.assume(secondaryHolder != address(tokenMock));
        vm.assume(to != secondaryHolder);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stake(tokenId);
        tokenMock.transferFrom(to, secondaryHolder, tokenId);
        vm.stopPrank();

        vm.startPrank(secondaryHolder);
        tokenMock.unstake(tokenId);
        vm.stopPrank();

        vm.expectRevert("ERC721: invalid token ID");
        address ownerOfWrapper = tokenMock.ownerOf(tokenId);
        assertEq(wrappedTokenMock.ownerOf(tokenId), secondaryHolder);
    }

    function testStakeToSecondaryWrappingCollectionHoldersCanUnstakeTokens(
        address to,
        address secondaryHolder,
        uint256 tokenId,
        address stakeReceiver
    ) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(secondaryHolder != address(0));
        vm.assume(secondaryHolder != address(tokenMock));
        vm.assume(to != secondaryHolder);
        _sanitizeAddress(stakeReceiver);
        vm.assume(stakeReceiver != secondaryHolder);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        vm.startPrank(stakeReceiver);
        tokenMock.transferFrom(stakeReceiver, secondaryHolder, tokenId);
        vm.stopPrank();

        vm.startPrank(secondaryHolder);
        tokenMock.unstake(tokenId);
        vm.stopPrank();

        vm.expectRevert("ERC721: invalid token ID");
        address ownerOfWrapper = tokenMock.ownerOf(tokenId);
        assertEq(wrappedTokenMock.ownerOf(tokenId), secondaryHolder);
    }

    function testCanSetStakerConstraints(uint8 constraintsUint8) public {
        vm.assume(constraintsUint8 <= 2);
        StakerConstraints constraints = StakerConstraints(constraintsUint8);

        vm.expectEmit(false, false, false, true);
        emit StakerConstraintsSet(constraints);
        tokenMock.setStakerConstraints(constraints);
        assertEq(uint8(tokenMock.getStakerConstraints()), uint8(constraints));
    }

    function testRevertsWhenUnauthorizedUserAttemptsToSetStakerConstraints(
        address unauthorizedUser,
        uint8 constraintsUint8
    ) public {
        vm.assume(unauthorizedUser != address(0));
        vm.assume(unauthorizedUser != address(tokenMock));
        vm.assume(unauthorizedUser != address(this));
        vm.assume(constraintsUint8 <= 2);
        StakerConstraints constraints = StakerConstraints(constraintsUint8);

        vm.prank(unauthorizedUser);
        vm.expectRevert("Ownable: caller is not the owner");
        tokenMock.setStakerConstraints(constraints);
    }

    function testEOACanStakeTokensWhenStakerConstraintsAreInEffect(address to, uint256 tokenId) public {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(to.code.length == 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.CallerIsTxOrigin);

        vm.startPrank(to, to);
        tokenMock.stake(tokenId);
        vm.stopPrank();

        assertEq(tokenMock.ownerOf(tokenId), to);
        assertEq(wrappedTokenMock.ownerOf(tokenId), address(tokenMock));
    }

    function testStakeToEOACanStakeTokensWhenStakerConstraintsAreInEffect(address to, uint256 tokenId, address stakeReceiver) public {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(to.code.length == 0);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.CallerIsTxOrigin);

        vm.startPrank(to, stakeReceiver);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        assertEq(tokenMock.ownerOf(tokenId), stakeReceiver);
        assertEq(wrappedTokenMock.ownerOf(tokenId), address(tokenMock));
    }

    function testEOACanStakeTokensWhenEOAStakerConstraintsAreInEffectButValidatorIsUnset(address to, uint256 tokenId)
        public
    {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(to.code.length == 0);

        tokenMock.setTransferValidator(address(0));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.startPrank(to, to);
        tokenMock.stake(tokenId);
        vm.stopPrank();

        assertEq(tokenMock.ownerOf(tokenId), to);
        assertEq(wrappedTokenMock.ownerOf(tokenId), address(tokenMock));
    }

    function testStakeToEOACanStakeTokensWhenEOAStakerConstraintsAreInEffectButValidatorIsUnset(address to, uint256 tokenId, address stakeReceiver)
        public
    {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(to.code.length == 0);
        _sanitizeAddress(stakeReceiver);

        tokenMock.setTransferValidator(address(0));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.startPrank(to, to);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        assertEq(tokenMock.ownerOf(tokenId), stakeReceiver);
        assertEq(wrappedTokenMock.ownerOf(tokenId), address(tokenMock));
    }

    function testVerifiedEOACanStakeTokensWhenEOAStakerConstraintsAreInEffect(uint160 toKey, uint256 tokenId) public {
        address to = _verifyEOA(toKey);
        _sanitizeAddress(to);
        vm.assume(to != address(0));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.startPrank(to);
        tokenMock.stake(tokenId);
        vm.stopPrank();

        assertEq(tokenMock.ownerOf(tokenId), to);
        assertEq(wrappedTokenMock.ownerOf(tokenId), address(tokenMock));
    }

    function testStakeToVerifiedEOACanStakeTokensWhenEOAStakerConstraintsAreInEffect(uint160 toKey, uint256 tokenId, uint160 stakeReceiverKey) public {
        vm.assume(toKey != stakeReceiverKey);
        address to = _verifyEOA(toKey);
        address stakeReceiver = _verifyEOA(stakeReceiverKey);
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.startPrank(to);
        tokenMock.stakeTo(tokenId, stakeReceiver);
        vm.stopPrank();

        assertEq(tokenMock.ownerOf(tokenId), stakeReceiver);
        assertEq(wrappedTokenMock.ownerOf(tokenId), address(tokenMock));
    }

    function testRevertsWhenCallerIsTxOriginConstraintIsInEffectIfCallerIsNotOrigin(
        address to,
        address origin,
        uint256 tokenId
    ) public {
        _sanitizeAddress(to);
        _sanitizeAddress(origin);
        vm.assume(to != address(0));
        vm.assume(origin != address(0));
        vm.assume(to != origin);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.CallerIsTxOrigin);

        vm.prank(to, origin);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__SmartContractsNotPermittedToStake.selector);
        tokenMock.stake(tokenId);
    }

    function testStakeToRevertsWhenCallerIsTxOriginConstraintIsInEffectIfCallerIsNotOrigin(
        address to,
        address origin,
        uint256 tokenId,
        address stakeReceiver
    ) public {
        _sanitizeAddress(to);
        _sanitizeAddress(origin);
        vm.assume(to != address(0));
        vm.assume(origin != address(0));
        vm.assume(to != origin);
        _sanitizeAddress(stakeReceiver);
        vm.assume(stakeReceiver != to);
        vm.assume(stakeReceiver != origin);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.CallerIsTxOrigin);

        vm.prank(to, origin);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__SmartContractsNotPermittedToStake.selector);
        tokenMock.stakeTo(tokenId, stakeReceiver);
    }

    function testRevertsWhenCallerIsEOAConstraintIsInEffectIfCallerHasNotVerifiedSignature(address to, uint256 tokenId)
        public
    {
        _sanitizeAddress(to);
        vm.assume(to != address(0));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.prank(to);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerSignatureNotVerifiedInEOARegistry.selector);
        tokenMock.stake(tokenId);
    }

    function testStakeToRevertsWhenCallerIsEOAConstraintIsInEffectIfCallerHasNotVerifiedSignature(address to, uint256 tokenId, address stakeReceiver)
        public
    {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, tokenId);
        wrappedTokenMock.setApprovalForAll(address(tokenMock), true);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.prank(to);
        vm.expectRevert(ERC721WrapperBase.ERC721WrapperBase__CallerSignatureNotVerifiedInEOARegistry.selector);
        tokenMock.stakeTo(tokenId, stakeReceiver);
    }

    function _sanitizeAddress(address addr) internal view virtual override {
        super._sanitizeAddress(addr);
        vm.assume(addr != address(tokenMock));
        vm.assume(addr != address(wrappedTokenMock));
    }
}