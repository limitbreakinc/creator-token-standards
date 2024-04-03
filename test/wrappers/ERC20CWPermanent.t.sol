// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../mocks/ERC20Mock.sol";
import "../mocks/ERC20CWPermanentMock.sol";
import "../CreatorTokenFungible.t.sol";

contract ERC20CWPermanentTest is CreatorTokenFungibleTest {
    event Staked(uint256 indexed amount, address indexed account);
    event Unstaked(uint256 indexed amount, address indexed account);
    event StakerConstraintsSet(StakerConstraints stakerConstraints);

    uint8 private constant DEFAULT_DECIMALS = 18;

    ERC20Mock public wrappedTokenMock;
    ERC20CWPermanentMock public tokenMock;

    function setUp() public virtual override {
        super.setUp();

        wrappedTokenMock = new ERC20Mock(DEFAULT_DECIMALS);
        tokenMock = new ERC20CWPermanentMock(address(wrappedTokenMock), DEFAULT_DECIMALS);
    }

    function _deployNewToken(address creator) internal virtual override returns (ITestCreatorToken) {
        vm.startPrank(creator);
        address wrappedToken = address(new ERC20Mock(DEFAULT_DECIMALS));
        ITestCreatorToken token = ITestCreatorToken(address(new ERC20CWPermanentMock(wrappedToken, DEFAULT_DECIMALS)));
        vm.stopPrank();
        return token;
    }

    function _mintToken(address tokenAddress, address to, uint256 amount) internal virtual override {
        address wrappedTokenAddress = ERC20CWPermanentMock(tokenAddress).getWrappedCollectionAddress();
        vm.startPrank(to);
        ERC20Mock(wrappedTokenAddress).mint(to, amount);
        ERC20Mock(wrappedTokenAddress).approve(tokenAddress, type(uint256).max);
        ERC20CWPermanentMock(tokenAddress).mint(to, amount);
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

    function testCanUnstakeReturnsFalseWhenTokensDoNotExist(uint256 amount) public {
        vm.assume(amount > 0);
        assertFalse(tokenMock.canUnstake(amount));
    }

    function testCanUnstakeReturnsFalseForStakedamounts(address to, uint256 amount) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        _mintToken(address(tokenMock), to, amount);
        assertFalse(tokenMock.canUnstake(amount));
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

    function testRevertsWhenUnauthorizedUserAttemptsToStake(address to, address unauthorizedUser, uint256 amount)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(unauthorizedUser);
        vm.expectRevert(ERC20WrapperBase.ERC20WrapperBase__InsufficientBalanceOfWrappedToken.selector);
        tokenMock.stake(amount);
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

    function testRevertsWhenUnauthorizedUserAttemptsToUnstake(address to, address unauthorizedUser, uint256 amount)
        public
    {
        vm.assume(to != address(0));
        vm.assume(unauthorizedUser != address(0));
        vm.assume(to != unauthorizedUser);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);

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

    function testRevertsWhenApprovedOperatorAttemptsToUnstake(address to, address approvedOperator, uint256 amount)
        public
    {
        vm.assume(to != address(0));
        vm.assume(approvedOperator != address(0));
        vm.assume(to != approvedOperator);
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);

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

    function testWrappingCollectionHoldersCannotUnstakeTokens(address to, uint256 amount) public {
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stake(amount);
        vm.expectRevert(ERC20CWPermanent.ERC20CWPermanent__UnstakeIsNotPermitted.selector);
        tokenMock.unstake(amount);
        vm.stopPrank();
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
        vm.expectRevert(ERC20CWPermanent.ERC20CWPermanent__UnstakeIsNotPermitted.selector);
        tokenMock.unstake{value: value}(amount);
        vm.stopPrank();
    }

    function testSecondaryWrappingCollectionHoldersCannotUnstakeTokens(
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
        vm.expectRevert(ERC20CWPermanent.ERC20CWPermanent__UnstakeIsNotPermitted.selector);
        tokenMock.unstake(amount);
        vm.stopPrank();
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

    function _sanitizeAddress(address addr) internal view virtual override {
        super._sanitizeAddress(addr);
        vm.assume(addr != address(tokenMock));
        vm.assume(addr != address(wrappedTokenMock));
    }
}
