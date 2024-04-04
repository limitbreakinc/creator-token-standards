// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../mocks/RejectEtherMock.sol";
import "../mocks/ERC20Mock.sol";
import "../mocks/ERC20CWPaidUnstakeMock.sol";
import "../CreatorTokenFungible.t.sol";

contract ERC20CWPaidUnstakeTest is CreatorTokenFungibleTest {
    event Staked(uint256 indexed amount, address indexed account);
    event Unstaked(uint256 indexed amount, address indexed account);
    event StakerConstraintsSet(StakerConstraints stakerConstraints);

    uint8 private constant DEFAULT_DECIMALS = 18;
    uint256 private constant DEFAULT_UNSTAKE_UNIT_PRICE = 1 ether;

    ERC20Mock public wrappedTokenMock;
    ERC20CWPaidUnstakeMock public tokenMock;

    function setUp() public virtual override {
        super.setUp();

        wrappedTokenMock = new ERC20Mock(DEFAULT_DECIMALS);
        tokenMock = new ERC20CWPaidUnstakeMock(DEFAULT_UNSTAKE_UNIT_PRICE, address(wrappedTokenMock), DEFAULT_DECIMALS);
    }

    function _deployNewToken(address creator) internal virtual override returns (ITestCreatorToken) {
        vm.startPrank(creator);
        address wrappedToken = address(new ERC20Mock(DEFAULT_DECIMALS));
        ITestCreatorToken token = ITestCreatorToken(address(new ERC20CWPaidUnstakeMock(DEFAULT_UNSTAKE_UNIT_PRICE, wrappedToken, DEFAULT_DECIMALS)));
        vm.stopPrank();
        return token;
    }

    function _mintToken(address tokenAddress, address to, uint256 amount) internal virtual override {
        address wrappedTokenAddress = ERC20CWPaidUnstakeMock(tokenAddress).getWrappedCollectionAddress();
        vm.startPrank(to);
        ERC20Mock(wrappedTokenAddress).mint(to, amount);
        ERC20Mock(wrappedTokenAddress).approve(tokenAddress, type(uint256).max);
        ERC20CWPaidUnstakeMock(tokenAddress).mint(to, amount);
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
        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), 0);
        vm.stopPrank();
    }

    function testWrappingCollectionHoldersCannotUnstakeTokensIfStakePriceUnderpaid(address to, uint256 amount)
        public
    {
        
        amount = amount / DEFAULT_UNSTAKE_UNIT_PRICE;
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);

        uint256 underpayment = (tokenMock.getUnstakeUnitPrice() * amount) - 1;
        vm.deal(to, underpayment);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stake(amount);
        vm.expectRevert(ERC20CWPaidUnstake.ERC20CWPaidUnstake__IncorrectUnstakePayment.selector);
        tokenMock.unstake{value: underpayment}(amount);
        vm.stopPrank();
    }

    function testWrappingCollectionHoldersCannotUnstakeTokensIfStakePriceOverpaid(address to, uint256 amount) public {
        
        amount = amount / DEFAULT_UNSTAKE_UNIT_PRICE;
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);

        uint256 overpayment = (tokenMock.getUnstakeUnitPrice() * amount) + 1;
        vm.deal(to, overpayment);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stake(amount);
        vm.expectRevert(ERC20CWPaidUnstake.ERC20CWPaidUnstake__IncorrectUnstakePayment.selector);
        tokenMock.unstake{value: overpayment}(amount);
        vm.stopPrank();
    }

    function testWrappingCollectionHoldersCanUnstakeTokensIfExactStakePriceIsPaid(address to, uint256 amount) public returns (uint256 unstakePayment) {
        amount = amount / DEFAULT_UNSTAKE_UNIT_PRICE;
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);

        unstakePayment = (tokenMock.getUnstakeUnitPrice() * amount);
        vm.deal(to, unstakePayment);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stake(amount);
        tokenMock.unstake{value: unstakePayment}(amount);
        vm.stopPrank();

        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), 0);
        assertEq(wrappedTokenMock.balanceOf(to), amount);
    }

    function testOwnerCanWithdrawETHAfterPaidUnstake(address to, uint256 amount, address recipient) public {
        vm.assume(uint256(uint160(recipient)) > 0xFF);
        uint256 unstakePayment = testWrappingCollectionHoldersCanUnstakeTokensIfExactStakePriceIsPaid(to, amount);

        vm.expectEmit(true, true, true, true);
        emit WithdrawETH.Withdrawal(recipient, unstakePayment);
        tokenMock.withdrawETH(payable(recipient), unstakePayment);
    }

    function testRevertsIfNonOwnerWithdrawETHAfterPaidUnstake(address to, uint256 amount, address recipient, address unauthorizedUser) public {
        vm.assume(uint256(uint160(recipient)) > 0xFF);
        vm.assume(uint256(uint160(unauthorizedUser)) > 0xFF);
        vm.assume(unauthorizedUser != address(this));
        uint256 unstakePayment = testWrappingCollectionHoldersCanUnstakeTokensIfExactStakePriceIsPaid(to, amount);

        vm.expectRevert();
        vm.prank(unauthorizedUser);
        tokenMock.withdrawETH(payable(recipient), unstakePayment);
    }

    function testRevertWithdrawAmountIsZero(address to, uint256 amount, address recipient) public {
        vm.assume(uint256(uint160(recipient)) > 0xFF);
        testWrappingCollectionHoldersCanUnstakeTokensIfExactStakePriceIsPaid(to, amount);

        vm.expectRevert(WithdrawETH.WithdrawETH__AmountMustBeGreaterThanZero.selector);
        tokenMock.withdrawETH(payable(recipient), 0);
    }

    function testRevertWithdrawToAddressThatDoesNotAcceptEther(address to, uint256 amount) public {
        testWrappingCollectionHoldersCanUnstakeTokensIfExactStakePriceIsPaid(to, amount);

        address rejectEther = address(new RejectEtherMock());

        vm.expectRevert(WithdrawETH.WithdrawETH__AmountMustBeGreaterThanZero.selector);
        tokenMock.withdrawETH(payable(rejectEther), 0);
    }

    function testRevertWithdrawAmountIsGreaterThanContractBalance(address to, uint256 amount, address recipient) public {
        vm.assume(amount < type(uint96).max);
        vm.assume(uint256(uint160(recipient)) > 0xFF);
        testWrappingCollectionHoldersCanUnstakeTokensIfExactStakePriceIsPaid(to, amount);

        vm.expectRevert(WithdrawETH.WithdrawETH__InsufficientBalance.selector);
        tokenMock.withdrawETH(payable(recipient), type(uint256).max);
    }

    function testRevertRecipientIsTheZeroAddress(address to, uint256 amount) public {
        uint256 unstakePayment = testWrappingCollectionHoldersCanUnstakeTokensIfExactStakePriceIsPaid(to, amount);

        vm.expectRevert(WithdrawETH.WithdrawETH__RecipientMustBeNonZeroAddress.selector);
        tokenMock.withdrawETH(payable(address(0)), unstakePayment);
    }

    function testSecondaryWrappingCollectionHoldersCanUnstakeTokensByPayingStakePrice(
        address to,
        address secondaryHolder,
        uint256 amount
    ) public {
        
        amount = amount / DEFAULT_UNSTAKE_UNIT_PRICE;
        vm.assume(to != address(0));
        vm.assume(to != address(tokenMock));
        vm.assume(amount > 0);
        vm.assume(secondaryHolder != address(0));
        vm.assume(secondaryHolder != address(tokenMock));
        vm.assume(to != secondaryHolder);

        uint256 unstakePayment = (tokenMock.getUnstakeUnitPrice() * amount);
        vm.deal(secondaryHolder, unstakePayment);

        vm.startPrank(to);
        wrappedTokenMock.mint(to, amount);
        wrappedTokenMock.approve(address(tokenMock), type(uint256).max);
        tokenMock.stake(amount);
        tokenMock.transfer(secondaryHolder, amount);
        vm.stopPrank();

        vm.startPrank(secondaryHolder);
        tokenMock.unstake{value: unstakePayment}(amount);
        vm.stopPrank();

        assertEq(wrappedTokenMock.balanceOf(address(tokenMock)), 0);
        assertEq(wrappedTokenMock.balanceOf(secondaryHolder), amount);
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
