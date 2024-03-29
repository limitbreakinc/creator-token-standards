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
import "src/utils/EOARegistry.sol";

abstract contract CreatorTokenTest is Events, Helpers {
    EOARegistry public eoaRegistry;
    CreatorTokenTransferValidator public validator;

    function setUp() public virtual override {
        super.setUp();

        eoaRegistry = new EOARegistry();
        validator = new CreatorTokenTransferValidator(address(this), address(eoaRegistry), "", "");
    }

    function _verifyEOA(uint160 toKey) internal returns (address to) {
        toKey = uint160(bound(toKey, 1, type(uint160).max));
        to = vm.addr(toKey);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(toKey, ECDSA.toEthSignedMessageHash(bytes(eoaRegistry.MESSAGE_TO_SIGN())));
        vm.prank(to);
        eoaRegistry.verifySignatureVRS(v, r, s);
    }

    function _deployNewToken(address creator) internal virtual returns (ITestCreatorToken);

    function _mintToken(address tokenAddress, address to, uint256 tokenId) internal virtual {
        ITestCreatorToken(tokenAddress).mint(to, tokenId);
    }

    function _mintToken(address tokenAddress, address to, uint256 tokenId, uint256 amount) internal virtual {
        ITestCreatorToken(tokenAddress).mint(to, tokenId, amount);
    }

    function testGetTransferValidatorReturnsTransferValidatorAddressBeforeValidatorIsSet(address creator) public {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);
        assertEq(address(token.getTransferValidator()), token.DEFAULT_TRANSFER_VALIDATOR());
    }

    function testRevertsWhenSetTransferValidatorCalledWithContractThatHasCodeLengthZero(address creator, address validator) public {
        _sanitizeAddress(creator);
        _sanitizeAddress(validator);

        ITestCreatorToken token = _deployNewToken(creator);

        vm.startPrank(creator);
        vm.expectRevert(CreatorTokenBase.CreatorTokenBase__InvalidTransferValidatorContract.selector);
        token.setTransferValidator(validator);
        vm.stopPrank();
    }

    function testAllowsAnyAddressToBeSetAsValidatorIfItHasCode(address creator, address validator, bytes32 code) public {
        _sanitizeAddress(creator);
        _sanitizeAddress(validator);

        ITestCreatorToken token = _deployNewToken(creator);

        vm.etch(validator, abi.encode(code));

        vm.startPrank(creator);
        token.setTransferValidator(validator);
        vm.stopPrank();

        assertEq(token.getTransferValidator(), validator);
    }

    function testAllowsValidatorToBeSetBackToZeroAddress(address creator, address validator, bytes32 code) public {
        _sanitizeAddress(creator);
        _sanitizeAddress(validator);

        ITestCreatorToken token = _deployNewToken(creator);

        vm.etch(validator, abi.encode(code));

        vm.startPrank(creator);
        token.setTransferValidator(validator);
        token.setTransferValidator(address(0));
        vm.stopPrank();

        assertEq(address(token.getTransferValidator()), address(0));
    }

    function testIsApprovedForAllDefaultsToFalseForTransferValidator(address validator, address creator, address owner, bytes32 code) public {
        _sanitizeAddress(validator);
        _sanitizeAddress(creator);
        _sanitizeAddress(owner);

        vm.etch(validator, abi.encode(code));

        ITestCreatorToken token = _deployNewToken(creator);
        vm.prank(creator);
        token.setTransferValidator(address(validator));

        assertFalse(token.isApprovedForAll(owner, address(validator)));
    }

    function testIsApprovedForAllReturnsTrueForTransferValidatorIfAutoApproveEnabledByCreator(address validator, address creator, address owner, bytes32 code) public {
        _sanitizeAddress(validator);
        _sanitizeAddress(creator);
        _sanitizeAddress(owner);

        vm.etch(validator, abi.encode(code));

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

        ITestCreatorToken token = _deployNewToken(creator);
        vm.startPrank(creator);
        token.setAutomaticApprovalOfTransfersFromValidator(true);
        vm.stopPrank();

        assertTrue(token.isApprovedForAll(owner, token.DEFAULT_TRANSFER_VALIDATOR()));
    }

    function testIsApprovedForAllReturnsTrueWhenUserExplicitlyApprovesTransferValidator(address validator, address creator, address owner, bytes32 code) public {
        _sanitizeAddress(validator);
        _sanitizeAddress(creator);
        _sanitizeAddress(owner);
        vm.assume(validator != owner);

        vm.etch(validator, abi.encode(code));

        ITestCreatorToken token = _deployNewToken(creator);
        vm.prank(creator);
        token.setTransferValidator(address(validator));

        vm.prank(owner);
        token.setApprovalForAll(address(validator), true);

        assertTrue(token.isApprovedForAll(owner, address(validator)));
    }
}
