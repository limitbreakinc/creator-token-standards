// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../mocks/ERC20Mock.sol";
import "../mocks/ERC20Mock.sol";
import "../mocks/ERC20CWMock.sol";
import "../mocks/ClonerMock.sol";
import "../CreatorTokenFungible.t.sol";

contract ERC20CWTest is CreatorTokenFungibleTest {
    event Staked(uint256 indexed amount, address indexed account);
    event Unstaked(uint256 indexed amount, address indexed account);
    event StakerConstraintsSet(StakerConstraints stakerConstraints);

    uint8 private constant DEFAULT_DECIMALS = 18;

    ERC20Mock public wrappedTokenMock;
    ERC20CWMock public tokenMock;

    function setUp() public virtual override {
        super.setUp();

        wrappedTokenMock = new ERC20Mock(DEFAULT_DECIMALS);
        tokenMock = new ERC20CWMock(address(wrappedTokenMock), DEFAULT_DECIMALS);
        //TODO: tokenMock.setToCustomValidatorAndSecurityPolicy(address(validator), TransferSecurityLevels.Two, 0);
    }

    function _deployNewToken(address creator) internal virtual override returns (ITestCreatorToken) {
        vm.startPrank(creator);
        address wrappedToken = address(new ERC20Mock(DEFAULT_DECIMALS));
        ITestCreatorToken token = ITestCreatorToken(address(new ERC20CWMock(wrappedToken, DEFAULT_DECIMALS)));
        vm.stopPrank();
        return token;
    }

    function testRevertsWhenDeployingWithZeroAddressWrapper() public {
        address wrappedToken = address(0);

        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InvalidERC20Collection.selector);
        ERC20CWMock newMock = new ERC20CWMock(wrappedToken, DEFAULT_DECIMALS);
    }

    function testRevertsWhenDeployingWithZeroCodeLengthWrapper() public {
        address wrappedToken = address(uint160(uint256(keccak256(abi.encode(0)))));

        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InvalidERC20Collection.selector);
        ERC20CWMock newMock = new ERC20CWMock(wrappedToken, DEFAULT_DECIMALS);
    }

    function _mintToken(address tokenAddress, address to, uint256 amount) internal virtual override {
        address wrappedTokenAddress = ERC20CWMock(tokenAddress).getWrappedCollectionAddress();
        vm.startPrank(to);
        ERC20Mock(wrappedTokenAddress).mint(to, amount);
        ERC20Mock(wrappedTokenAddress).approve(tokenAddress, type(uint256).max);
        ERC20CWMock(tokenAddress).mint(to, amount);
        vm.stopPrank();
    }

    function testSupportedTokenInterfaces() public {
        assertEq(tokenMock.supportsInterface(type(ICreatorToken).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(ICreatorTokenWrapperERC20).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC20).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC20Metadata).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC165).interfaceId), true);
    }

    function testGetTransferValidationFunction() public override {
        (bytes4 functionSignature, bool isViewFunction) = tokenMock.getTransferValidationFunction();

        assertEq(functionSignature, bytes4(keccak256("validateTransfer(address,address,address,uint256,uint256)")));
        assertEq(isViewFunction, false);
    }

    function testRevertsWhenWrappingZeroAddress() public {
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InvalidERC20Collection.selector);
        new ERC20CWMock(address(0), DEFAULT_DECIMALS);
    }

    function testRevertsWhenWrappingNoCode(address noCodeToken) public {
        vm.assume(noCodeToken.code.length == 0);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InvalidERC20Collection.selector);
        new ERC20CWMock(noCodeToken, DEFAULT_DECIMALS);
    }

    function testCanUnstakeReturnsFalseWhenTokensDoNotExist(uint256 amount) public {
        vm.assume(amount > 0);
        assertFalse(tokenMock.canUnstake(amount));
    }

    function testCanUnstakeReturnsTrueForStakedamounts(address to, uint256 amount) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        _mintToken(address(tokenMock), to, amount);
        assertTrue(tokenMock.canUnstake(amount));
    }

    function testWrappedCollectionHoldersCanStakeTokens(address to, uint256 amount) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stake(amount);
        vm.stopPrank();

        assertEq(tokenMock.balanceOf(to), amount);
        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), amount);
    }

    function testStakeToWrappedCollectionHoldersCanStakeTokens(address to, uint256 amount, address stakeReceiver) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        assertEq(tokenMock.balanceOf(stakeReceiver), amount);
        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), amount);
    }

    function testRevertsWhenStakeZeroAmount(address to) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, 1);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__AmountMustBeGreaterThanZero.selector);
        tokenMock.stake(0);
        vm.stopPrank();
    }

    function testRevertsWhenStakeToZeroAmount(address to) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, 1);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__AmountMustBeGreaterThanZero.selector);
        tokenMock.stakeTo(0, address(0x0b0b));
        vm.stopPrank();
    }

    function testRevertsWhenNativeFundsIncludedInStake(address to, uint256 amount, uint256 value) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(value > 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.deal(to, value);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__DefaultImplementationOfStakeDoesNotAcceptPayment.selector);
        tokenMock.stake{value: value}(amount);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenNativeFundsIncludedInStake(address to, uint256 amount, uint256 value, address stakeReceiver) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(value > 0);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.deal(to, value);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__DefaultImplementationOfStakeDoesNotAcceptPayment.selector);
        tokenMock.stakeTo{value: value}(amount, stakeReceiver);
        vm.stopPrank();
    }

    function testRevertsWhenUnauthorizedUserAttemptsToStake(address to, address unauthorizedUser, uint256 amount)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(wrappedTokenMock.balanceOf(unauthorizedUser) < amount);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(unauthorizedUser);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappedToken.selector);
        tokenMock.stake(amount);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenUnauthorizedUserAttemptsToStake(address to, address unauthorizedUser, uint256 amount, address stakeReceiver)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(wrappedTokenMock.balanceOf(unauthorizedUser) < amount);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(unauthorizedUser);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappedToken.selector);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();
    }

    function testRevertsWhenApprovedOperatorAttemptsToStake(address to, address approvedOperator, uint256 amount)
        public
    {
        vm.assume(to != address(0));
        vm.assume(approvedOperator != address(0));
        vm.assume(to != approvedOperator);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(wrappedTokenMock.balanceOf(approvedOperator) < amount);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        wrappedTokenMock.approve(approvedOperator, type(uint256).max);
        vm.stopPrank();

        vm.startPrank(approvedOperator);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappedToken.selector);
        tokenMock.stake(amount);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenApprovedOperatorAttemptsToStake(address to, address approvedOperator, uint256 amount, address stakeReceiver)
        public
    {
        vm.assume(to != address(0));
        vm.assume(approvedOperator != address(0));
        vm.assume(to != approvedOperator);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(wrappedTokenMock.balanceOf(approvedOperator) < amount);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        wrappedTokenMock.approve(approvedOperator, type(uint256).max);
        vm.stopPrank();

        vm.startPrank(approvedOperator);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappedToken.selector);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();
    }

    function testRevertsWhenUnauthorizedUserAttemptsToUnstake(address to, address unauthorizedUser, uint256 amount)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(tokenMock.balanceOf(unauthorizedUser) < amount);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stake(amount);
        vm.stopPrank();

        vm.startPrank(unauthorizedUser);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappingToken.selector);
        tokenMock.unstake(amount);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenUnauthorizedUserAttemptsToUnstake(address to, address unauthorizedUser, uint256 amount, address stakeReceiver)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(tokenMock.balanceOf(unauthorizedUser) < amount);
        _sanitizeAddress(stakeReceiver);
        vm.assume(stakeReceiver != unauthorizedUser);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        vm.startPrank(unauthorizedUser);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappingToken.selector);
        tokenMock.unstake(amount);
        vm.stopPrank();
    }

    function testRevertsWhenApprovedOperatorAttemptsToUnstake(address to, address approvedOperator, uint256 amount)
        public
    {
        vm.assume(to != address(0));
        vm.assume(approvedOperator != address(0));
        vm.assume(to != approvedOperator);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(tokenMock.balanceOf(approvedOperator) < amount);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        wrappedTokenMock.approve(approvedOperator, type(uint256).max);
        tokenMock.approve(approvedOperator, type(uint256).max);
        tokenMock.stake(amount);
        vm.stopPrank();

        vm.startPrank(approvedOperator);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappingToken.selector);
        tokenMock.unstake(amount);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenApprovedOperatorAttemptsToUnstake(address to, address approvedOperator, uint256 amount, address stakeReceiver)
        public
    {
        vm.assume(to != address(0));
        vm.assume(approvedOperator != address(0));
        vm.assume(to != approvedOperator);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(tokenMock.balanceOf(approvedOperator) < amount);
        _sanitizeAddress(stakeReceiver);
        vm.assume(stakeReceiver != approvedOperator);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        wrappedTokenMock.approve(approvedOperator, type(uint256).max);
        tokenMock.approve(approvedOperator, type(uint256).max);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        vm.prank(stakeReceiver);
        tokenMock.approve(approvedOperator, type(uint256).max);

        vm.startPrank(approvedOperator);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappingToken.selector);
        tokenMock.unstake(amount);
        vm.stopPrank();
    }

    function testRevertsWhenUserAttemptsToUnstakeATokenThatHasNotBeenStaked(address to, uint256 amount) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappingToken.selector);
        tokenMock.unstake(amount);
        vm.stopPrank();
    }

    function testWrappingCollectionHoldersCanUnstakeTokens(address to, uint256 amount) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stake(amount);
        tokenMock.unstake(amount);
        vm.stopPrank();

        assertEq(wrappedTokenMock.balanceOf(to), amount);
        assertEq(tokenMock.balanceOf(to), 0);
    }

    function testStakeToWrappingCollectionHoldersCanUnstakeTokens(address to, uint256 amount, address stakeReceiver) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        vm.prank(stakeReceiver);
        tokenMock.unstake(amount);

        assertEq(wrappedTokenMock.balanceOf(stakeReceiver), amount);
        assertEq(tokenMock.balanceOf(stakeReceiver), 0);
    }

    function testRevertsWhenNativeFundsIncludedInUnstakeCall(address to, uint256 amount, uint256 value) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(value > 0);

        vm.deal(to, value);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stake(amount);
        vm.expectRevert(
            ERC20WrapperBase.ERC20WrapperBase__DefaultImplementationOfUnstakeDoesNotAcceptPayment.selector
        );
        tokenMock.unstake{value: value}(amount);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenNativeFundsIncludedInUnstakeCall(address to, uint256 amount, uint256 value, address stakeReceiver) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(value > 0);
        _sanitizeAddress(stakeReceiver);

        vm.deal(stakeReceiver, value);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        vm.prank(stakeReceiver);
        vm.expectRevert(
            ERC20WrapperBase.ERC20WrapperBase__DefaultImplementationOfUnstakeDoesNotAcceptPayment.selector
        );
        tokenMock.unstake{value: value}(amount);
    }

    function testSecondaryWrappingCollectionHoldersCanUnstakeTokens(
        address to,
        address secondaryHolder,
        uint256 amount
    ) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(secondaryHolder != address(0));
        vm.assume(secondaryHolder != address(tokenMock));
        vm.assume(to != secondaryHolder);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stake(amount);
        tokenMock.transfer(secondaryHolder, amount);
        vm.stopPrank();

        vm.startPrank(secondaryHolder);
        tokenMock.unstake(amount);
        vm.stopPrank();

        assertEq(wrappedTokenMock.balanceOf(secondaryHolder), amount);
        assertEq(tokenMock.balanceOf(secondaryHolder), 0);
    }

    function testStakeToSecondaryWrappingCollectionHoldersCanUnstakeTokens(
        address to,
        address secondaryHolder,
        uint256 amount,
        address stakeReceiver
    ) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(secondaryHolder != address(0));
        vm.assume(secondaryHolder != address(tokenMock));
        vm.assume(to != secondaryHolder);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        vm.startPrank(stakeReceiver);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.transfer(secondaryHolder, amount);
        vm.stopPrank();

        vm.startPrank(secondaryHolder);
        tokenMock.unstake(amount);
        vm.stopPrank();

        assertEq(wrappedTokenMock.balanceOf(secondaryHolder), amount);
        assertEq(tokenMock.balanceOf(secondaryHolder), 0);
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

    function testEOACanStakeTokensWhenStakerConstraintsAreInEffect(address to, uint256 amount) public {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(to.code.length == 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.CallerIsTxOrigin);

        vm.startPrank(to, to);
        tokenMock.stake(amount);
        vm.stopPrank();

        assertEq(tokenMock.balanceOf(to), amount);
        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), amount);
    }

    function testStakeToEOACanStakeTokensWhenStakerConstraintsAreInEffect(address to, uint256 amount, address stakeReceiver) public {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(to.code.length == 0);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.CallerIsTxOrigin);

        vm.startPrank(to, stakeReceiver);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        assertEq(tokenMock.balanceOf(stakeReceiver), amount);
        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), amount);
    }

    function testEOACanStakeTokensWhenEOAStakerConstraintsAreInEffectButValidatorIsUnset(address to, uint256 amount)
        public
    {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(to.code.length == 0);

        tokenMock.setTransferValidator(address(0));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.startPrank(to, to);
        tokenMock.stake(amount);
        vm.stopPrank();

        assertEq(tokenMock.balanceOf(to), amount);
        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), amount);
    }

    function testStakeToEOACanStakeTokensWhenEOAStakerConstraintsAreInEffectButValidatorIsUnset(address to, uint256 amount, address stakeReceiver)
        public
    {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(to.code.length == 0);
        _sanitizeAddress(stakeReceiver);

        tokenMock.setTransferValidator(address(0));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.startPrank(to, stakeReceiver);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        assertEq(tokenMock.balanceOf(stakeReceiver), amount);
        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), amount);
    }

    function testVerifiedEOACanStakeTokensWhenEOAStakerConstraintsAreInEffect(uint160 toKey, uint256 amount) public {
        address to = _verifyEOA(toKey);
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(amount > 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.startPrank(to);
        tokenMock.stake(amount);
        vm.stopPrank();

        assertEq(tokenMock.balanceOf(to), amount);
        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), amount);
    }

    function testStakeToVerifiedEOACanStakeTokensWhenEOAStakerConstraintsAreInEffect(uint160 toKey, uint256 amount, uint160 stakeReceiverKey) public {
        vm.assume(toKey != stakeReceiverKey);
        vm.assume(amount > 0);

        address to = _verifyEOA(toKey);
        address stakeReceiver = _verifyEOA(stakeReceiverKey);
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.startPrank(to);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        assertEq(tokenMock.balanceOf(stakeReceiver), amount);
        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), amount);
    }

    function testRevertsWhenCallerIsTxOriginConstraintIsInEffectIfCallerIsNotOrigin(
        address to,
        address origin,
        uint256 amount
    ) public {
        _sanitizeAddress(to);
        _sanitizeAddress(origin);
        vm.assume(to != address(0));
        vm.assume(origin != address(0));
        vm.assume(to != origin);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.CallerIsTxOrigin);

        vm.prank(to, origin);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__SmartContractsNotPermittedToStake.selector);
        tokenMock.stake(amount);
    }

    function testStakeToRevertsWhenCallerIsTxOriginConstraintIsInEffectIfCallerIsNotOrigin(
        address to,
        address origin,
        uint256 amount,
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
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.CallerIsTxOrigin);

        vm.prank(to, origin);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__SmartContractsNotPermittedToStake.selector);
        tokenMock.stakeTo(amount, stakeReceiver);
    }

    function testRevertsWhenCallerIsEOAConstraintIsInEffectIfCallerHasNotVerifiedSignature(address to, uint256 amount)
        public
    {
        _sanitizeAddress(to);
        vm.assume(to != address(0));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.prank(to);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__CallerSignatureNotVerifiedInEOARegistry.selector);
        tokenMock.stake(amount);
    }

    function testStakeToRevertsWhenCallerIsEOAConstraintIsInEffectIfCallerHasNotVerifiedSignature(address to, uint256 amount, address stakeReceiver)
        public
    {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.prank(to);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__CallerSignatureNotVerifiedInEOARegistry.selector);
        tokenMock.stakeTo(amount, stakeReceiver);
    }

    function _sanitizeAddress(address addr) internal view virtual override {
        super._sanitizeAddress(addr);
        vm.assume(addr != address(tokenMock));
        vm.assume(addr != address(wrappedTokenMock));
    }
}

contract ERC20CWInitializableTest is CreatorTokenFungibleTest {
    event Staked(uint256 indexed amount, address indexed account);
    event Unstaked(uint256 indexed amount, address indexed account);
    event StakerConstraintsSet(StakerConstraints stakerConstraints);

    uint8 private constant DEFAULT_DECIMALS = 18;

    ClonerMock cloner;

    ERC20Mock wrappedTokenMock;

    ERC20CWInitializableMock public referenceTokenMock;
    ERC20CWInitializableMock public tokenMock;

    function setUp() public virtual override {
        super.setUp();

        cloner = new ClonerMock();

        wrappedTokenMock = new ERC20Mock(DEFAULT_DECIMALS);

        referenceTokenMock = new ERC20CWInitializableMock();

        bytes4[] memory initializationSelectors = new bytes4[](1);
        bytes[] memory initializationArguments = new bytes[](1);

        initializationSelectors[0] = referenceTokenMock.initializeWrappedCollectionAddress.selector;
        initializationArguments[0] = abi.encode(address(wrappedTokenMock));

        tokenMock = ERC20CWInitializableMock(
            cloner.cloneContract(
                address(referenceTokenMock), address(this), initializationSelectors, initializationArguments
            )
        );

        //TODO: tokenMock.setToCustomValidatorAndSecurityPolicy(address(validator), TransferSecurityLevels.Two, 0);
    }

    function _deployNewToken(address creator) internal virtual override returns (ITestCreatorToken) {
        vm.startPrank(creator);
        address wrappedToken = address(new ERC20Mock(DEFAULT_DECIMALS));

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

    function _mintToken(address tokenAddress, address to, uint256 amount) internal virtual override {
        address wrappedTokenAddress = ERC20CWInitializableMock(tokenAddress).getWrappedCollectionAddress();
        vm.startPrank(to);
        ERC20Mock(wrappedTokenAddress).mint(to, amount);
        ERC20Mock(wrappedTokenAddress).approve(tokenAddress, type(uint256).max);
        ERC20CWInitializableMock(tokenAddress).mint(to, amount);
        vm.stopPrank();
    }

    function testSupportedTokenInterfaces() public {
        assertEq(tokenMock.supportsInterface(type(ICreatorToken).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(ICreatorTokenWrapperERC20).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC20).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC20Metadata).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC165).interfaceId), true);
    }

    function testGetTransferValidationFunction() public override {
        (bytes4 functionSignature, bool isViewFunction) = tokenMock.getTransferValidationFunction();

        assertEq(functionSignature, bytes4(keccak256("validateTransfer(address,address,address,uint256,uint256)")));
        assertEq(isViewFunction, false);
    }

    function testInitializeAlreadyInitialized(address badAddress) public {
        vm.expectRevert(ERC20CWInitializable.ERC20CWInitializable__AlreadyInitializedWrappedCollection.selector);
        tokenMock.initializeWrappedCollectionAddress(badAddress);
    }

    function testRevertsWhenInitializingOwnerAgain(address badOwner) public {
        vm.expectRevert(OwnableInitializable.InitializableOwnable__OwnerAlreadyInitialized.selector);
        tokenMock.initializeOwner(badOwner);
    }

    function testCanUnstakeReturnsFalseWhenTokensDoNotExist(uint256 amount) public {
        vm.assume(amount > 0);
        assertFalse(tokenMock.canUnstake(amount));
    }

    function testCanUnstakeReturnsTrueForStakedamounts(address to, uint256 amount) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        _mintToken(address(tokenMock), to, amount);
        assertTrue(tokenMock.canUnstake(amount));
    }

    function testWrappedCollectionHoldersCanStakeTokens(address to, uint256 amount) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stake(amount);
        vm.stopPrank();

        assertEq(tokenMock.balanceOf(to), amount);
        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), amount);
    }

    function testStakeToWrappedCollectionHoldersCanStakeTokens(address to, uint256 amount, address stakeReceiver) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        assertEq(tokenMock.balanceOf(stakeReceiver), amount);
        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), amount);
    }

    function testRevertsWhenNativeFundsIncludedInStake(address to, uint256 amount, uint256 value) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(value > 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.deal(to, value);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__DefaultImplementationOfStakeDoesNotAcceptPayment.selector);
        tokenMock.stake{value: value}(amount);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenNativeFundsIncludedInStake(address to, uint256 amount, uint256 value, address stakeReceiver) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(value > 0);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.deal(to, value);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__DefaultImplementationOfStakeDoesNotAcceptPayment.selector);
        tokenMock.stakeTo{value: value}(amount, stakeReceiver);
        vm.stopPrank();
    }

    function testRevertsWhenUnauthorizedUserAttemptsToStake(address to, address unauthorizedUser, uint256 amount)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(wrappedTokenMock.balanceOf(unauthorizedUser) < amount);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(unauthorizedUser);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappedToken.selector);
        tokenMock.stake(amount);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenUnauthorizedUserAttemptsToStake(address to, address unauthorizedUser, uint256 amount, address stakeReceiver)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(wrappedTokenMock.balanceOf(unauthorizedUser) < amount);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(unauthorizedUser);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappedToken.selector);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();
    }

    function testRevertsWhenApprovedOperatorAttemptsToStake(address to, address approvedOperator, uint256 amount)
        public
    {
        vm.assume(to != address(0));
        vm.assume(approvedOperator != address(0));
        vm.assume(to != approvedOperator);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(wrappedTokenMock.balanceOf(approvedOperator) < amount);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        wrappedTokenMock.approve(approvedOperator, type(uint256).max);
        vm.stopPrank();

        vm.startPrank(approvedOperator);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappedToken.selector);
        tokenMock.stake(amount);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenApprovedOperatorAttemptsToStake(address to, address approvedOperator, uint256 amount, address stakeReceiver)
        public
    {
        vm.assume(to != address(0));
        vm.assume(approvedOperator != address(0));
        vm.assume(to != approvedOperator);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(wrappedTokenMock.balanceOf(approvedOperator) < amount);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        wrappedTokenMock.approve(approvedOperator, type(uint256).max);
        vm.stopPrank();

        vm.startPrank(approvedOperator);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappedToken.selector);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();
    }

    function testRevertsWhenUnauthorizedUserAttemptsToUnstake(address to, address unauthorizedUser, uint256 amount)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(tokenMock.balanceOf(unauthorizedUser) < amount);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stake(amount);
        vm.stopPrank();

        vm.startPrank(unauthorizedUser);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappingToken.selector);
        tokenMock.unstake(amount);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenUnauthorizedUserAttemptsToUnstake(address to, address unauthorizedUser, uint256 amount, address stakeReceiver)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(tokenMock.balanceOf(unauthorizedUser) < amount);
        _sanitizeAddress(stakeReceiver);
        vm.assume(stakeReceiver != unauthorizedUser);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        vm.startPrank(unauthorizedUser);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappingToken.selector);
        tokenMock.unstake(amount);
        vm.stopPrank();
    }

    function testRevertsWhenApprovedOperatorAttemptsToUnstake(address to, address approvedOperator, uint256 amount)
        public
    {
        vm.assume(to != address(0));
        vm.assume(approvedOperator != address(0));
        vm.assume(to != approvedOperator);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(tokenMock.balanceOf(approvedOperator) < amount);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        wrappedTokenMock.approve(approvedOperator, type(uint256).max);
        tokenMock.approve(approvedOperator, type(uint256).max);
        tokenMock.stake(amount);
        vm.stopPrank();

        vm.startPrank(approvedOperator);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappingToken.selector);
        tokenMock.unstake(amount);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenApprovedOperatorAttemptsToUnstake(address to, address approvedOperator, uint256 amount, address stakeReceiver)
        public
    {
        vm.assume(to != address(0));
        vm.assume(approvedOperator != address(0));
        vm.assume(to != approvedOperator);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(tokenMock.balanceOf(approvedOperator) < amount);
        _sanitizeAddress(stakeReceiver);
        vm.assume(stakeReceiver != approvedOperator);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        wrappedTokenMock.approve(approvedOperator, type(uint256).max);
        tokenMock.approve(approvedOperator, type(uint256).max);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        vm.startPrank(stakeReceiver);
        tokenMock.approve(approvedOperator, type(uint256).max);
        vm.stopPrank();

        vm.startPrank(approvedOperator);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappingToken.selector);
        tokenMock.unstake(amount);
        vm.stopPrank();
    }

    function testRevertsWhenUserAttemptsToUnstakeATokenThatHasNotBeenStaked(address to, uint256 amount) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappingToken.selector);
        tokenMock.unstake(amount);
        vm.stopPrank();
    }

    function testWrappingCollectionHoldersCanUnstakeTokens(address to, uint256 amount) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stake(amount);
        tokenMock.unstake(amount);
        vm.stopPrank();

        assertEq(wrappedTokenMock.balanceOf(to), amount);
        assertEq(tokenMock.balanceOf(to), 0);
    }

    function testStakeToWrappingCollectionHoldersCanUnstakeTokens(address to, uint256 amount, address stakeReceiver) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        vm.startPrank(stakeReceiver);
        tokenMock.unstake(amount);
        vm.stopPrank();

        assertEq(wrappedTokenMock.balanceOf(stakeReceiver), amount);
        assertEq(tokenMock.balanceOf(stakeReceiver), 0);
    }

    function testRevertsWhenNativeFundsIncludedInUnstakeCall(address to, uint256 amount, uint256 value) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(value > 0);

        vm.deal(to, value);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stake(amount);
        vm.expectRevert(
            ERC20WrapperBase.ERC20WrapperBase__DefaultImplementationOfUnstakeDoesNotAcceptPayment.selector
        );
        tokenMock.unstake{value: value}(amount);
        vm.stopPrank();
    }

    function testRevertsWhenUnstakingZeroAmount(address to, uint256 amount) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stake(amount);
        vm.expectRevert(
            ERC20WrapperBase.ERC20WrapperBase__AmountMustBeGreaterThanZero.selector
        );
        tokenMock.unstake(0);
        vm.stopPrank();
    }

    function testStakeToRevertsWhenNativeFundsIncludedInUnstakeCall(address to, uint256 amount, uint256 value, address stakeReceiver) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(value > 0);
        _sanitizeAddress(stakeReceiver);

        vm.deal(stakeReceiver, value);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        vm.startPrank(stakeReceiver);
        vm.expectRevert(
            ERC20WrapperBase.ERC20WrapperBase__DefaultImplementationOfUnstakeDoesNotAcceptPayment.selector
        );
        tokenMock.unstake{value: value}(amount);
        vm.stopPrank();
    }

    function testSecondaryWrappingCollectionHoldersCanUnstakeTokens(
        address to,
        address secondaryHolder,
        uint256 amount
    ) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(secondaryHolder != address(0));
        vm.assume(secondaryHolder != address(tokenMock));
        vm.assume(to != secondaryHolder);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stake(amount);
        tokenMock.transfer(secondaryHolder, amount);
        vm.stopPrank();

        vm.startPrank(secondaryHolder);
        tokenMock.unstake(amount);
        vm.stopPrank();

        assertEq(wrappedTokenMock.balanceOf(secondaryHolder), amount);
        assertEq(tokenMock.balanceOf(secondaryHolder), 0);
    }

    function testStakeToSecondaryWrappingCollectionHoldersCanUnstakeTokens(
        address to,
        address secondaryHolder,
        uint256 amount,
        address stakeReceiver
    ) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(secondaryHolder != address(0));
        vm.assume(secondaryHolder != address(tokenMock));
        vm.assume(to != secondaryHolder);
        _sanitizeAddress(stakeReceiver);
        vm.assume(stakeReceiver != secondaryHolder);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        vm.startPrank(stakeReceiver);
        tokenMock.transfer(secondaryHolder, amount);
        vm.stopPrank();

        vm.startPrank(secondaryHolder);
        tokenMock.unstake(amount);
        vm.stopPrank();

        assertEq(wrappedTokenMock.balanceOf(secondaryHolder), amount);
        assertEq(tokenMock.balanceOf(secondaryHolder), 0);
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

    function testEOACanStakeTokensWhenStakerConstraintsAreInEffect(address to, uint256 amount) public {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(to.code.length == 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.CallerIsTxOrigin);

        vm.startPrank(to, to);
        tokenMock.stake(amount);
        vm.stopPrank();

        assertEq(tokenMock.balanceOf(to), amount);
        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), amount);
    }

    function testStakeToEOACanStakeTokensWhenStakerConstraintsAreInEffect(address to, uint256 amount, address stakeReceiver) public {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(to.code.length == 0);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.CallerIsTxOrigin);

        vm.startPrank(to, stakeReceiver);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        assertEq(tokenMock.balanceOf(stakeReceiver), amount);
        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), amount);
    }

    function testEOACanStakeTokensWhenEOAStakerConstraintsAreInEffectButValidatorIsUnset(address to, uint256 amount)
        public
    {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(to.code.length == 0);

        tokenMock.setTransferValidator(address(0));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.startPrank(to, to);
        tokenMock.stake(amount);
        vm.stopPrank();

        assertEq(tokenMock.balanceOf(to), amount);
        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), amount);
    }

    function testStakeToEOACanStakeTokensWhenEOAStakerConstraintsAreInEffectButValidatorIsUnset(address to, uint256 amount, address stakeReceiver)
        public
    {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(to.code.length == 0);
        _sanitizeAddress(stakeReceiver);

        tokenMock.setTransferValidator(address(0));

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.startPrank(to, to);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        assertEq(tokenMock.balanceOf(stakeReceiver), amount);
        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), amount);
    }

    function testVerifiedEOACanStakeTokensWhenEOAStakerConstraintsAreInEffect(uint160 toKey, uint256 amount) public {
        address to = _verifyEOA(toKey);
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(amount > 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.startPrank(to);
        tokenMock.stake(amount);
        vm.stopPrank();

        assertEq(tokenMock.balanceOf(to), amount);
        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), amount);
    }

    function testStakeToVerifiedEOACanStakeTokensWhenEOAStakerConstraintsAreInEffect(uint160 toKey, uint256 amount, uint160 stakeReceiverKey) public {
        vm.assume(toKey != stakeReceiverKey);
        vm.assume(amount > 0);
        address to = _verifyEOA(toKey);
        address stakeReceiver = _verifyEOA(stakeReceiverKey);
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.startPrank(to);
        tokenMock.stakeTo(amount, stakeReceiver);
        vm.stopPrank();

        assertEq(tokenMock.balanceOf(stakeReceiver), amount);
        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), amount);
    }

    function testRevertsWhenCallerIsTxOriginConstraintIsInEffectIfCallerIsNotOrigin(
        address to,
        address origin,
        uint256 amount
    ) public {
        _sanitizeAddress(to);
        _sanitizeAddress(origin);
        vm.assume(to != address(0));
        vm.assume(origin != address(0));
        vm.assume(to != origin);
        vm.assume(amount > 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.CallerIsTxOrigin);

        vm.prank(to, origin);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__SmartContractsNotPermittedToStake.selector);
        tokenMock.stake(amount);
    }

    function testStakeToRevertsWhenCallerIsTxOriginConstraintIsInEffectIfCallerIsNotOrigin(
        address to,
        address origin,
        uint256 amount,
        address stakeReceiver
    ) public {
        _sanitizeAddress(to);
        _sanitizeAddress(origin);
        vm.assume(to != address(0));
        vm.assume(amount > 0);
        vm.assume(origin != address(0));
        vm.assume(to != origin);
        _sanitizeAddress(stakeReceiver);
        vm.assume(stakeReceiver != to);
        vm.assume(stakeReceiver != origin);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.CallerIsTxOrigin);

        vm.prank(to, origin);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__SmartContractsNotPermittedToStake.selector);
        tokenMock.stakeTo(amount, stakeReceiver);
    }

    function testRevertsWhenCallerIsEOAConstraintIsInEffectIfCallerHasNotVerifiedSignature(address to, uint256 amount)
        public
    {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(amount > 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.prank(to);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__CallerSignatureNotVerifiedInEOARegistry.selector);
        tokenMock.stake(amount);
    }

    function testStakeToRevertsWhenCallerIsEOAConstraintIsInEffectIfCallerHasNotVerifiedSignature(address to, uint256 amount, address stakeReceiver)
        public
    {
        _sanitizeAddress(to);
        vm.assume(to != address(0));
        vm.assume(amount > 0);
        _sanitizeAddress(stakeReceiver);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        tokenMock.setStakerConstraints(StakerConstraints.EOA);

        vm.prank(to);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__CallerSignatureNotVerifiedInEOARegistry.selector);
        tokenMock.stakeTo(amount, stakeReceiver);
    }

    function _sanitizeAddress(address addr) internal view virtual override {
        super._sanitizeAddress(addr);
        vm.assume(addr != address(tokenMock));
        vm.assume(addr != address(wrappedTokenMock));
    }
}
