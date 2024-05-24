// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/console.sol";
import "./mocks/ClonerMock.sol";
import "./mocks/ContractMock.sol";
import "./mocks/ERC721CMock.sol";
import "./interfaces/ITestCreatorToken.sol";
import "src/utils/TransferPolicy.sol";
import {CreatorTokenTransferValidator} from "src/utils/CreatorTokenTransferValidator.sol";
import "src/Constants.sol";
import "./utils/Events.sol";
import "./utils/Helpers.sol";
import "src/utils/EOARegistry.sol";
import "./CreatorToken.t.sol";

abstract contract CreatorTokenFungibleTest is CreatorTokenTest {
    function setUp() public virtual override {
        super.setUp();
    }

    function _mintToken(address tokenAddress, address to, uint256 amount) internal virtual {
        ITestCreatorToken(tokenAddress).mint(to, amount);
    }

    function testAllowanceDefaultsToZeroForTransferValidator(address validator, address creator, address owner, bytes32 code) public {
        _sanitizeAddress(creator);
        _sanitizeAddress(owner);

        ITestCreatorToken token = _deployNewToken(creator);
        address[] memory exclusionList = new address[](1);
        exclusionList[0] = address(token);
        _sanitizeAddress(validator, exclusionList);

        vm.etch(validator, abi.encode(code));
        
        vm.prank(creator);
        token.setTransferValidator(address(validator));

        assertEq(token.allowance(owner, address(validator)), 0);
    }

    function testAllowanceIsUnlimitedForTransferValidatorIfAutoApproveEnabledByCreator(address validator, address creator, address owner, bytes32 code) public {
        _sanitizeAddress(creator);
        _sanitizeAddress(owner);

        ITestCreatorToken token = _deployNewToken(creator);
        address[] memory exclusionList = new address[](1);
        exclusionList[0] = address(token);
        _sanitizeAddress(validator, exclusionList);

        vm.etch(validator, abi.encode(code));

        vm.startPrank(creator);
        token.setTransferValidator(address(validator));
        token.setAutomaticApprovalOfTransfersFromValidator(true);
        vm.stopPrank();

        assertEq(token.allowance(owner, address(validator)), type(uint256).max);
    }

    function testAllowanceUnlimitedForDefaultTransferValidatorIfAutoApproveEnabledByCreatorAndValidatorUninitialized(address creator, address owner) public {
        _sanitizeAddress(creator);
        _sanitizeAddress(owner);

        ITestCreatorToken token = _deployNewToken(creator);
        vm.startPrank(creator);
        token.setAutomaticApprovalOfTransfersFromValidator(true);
        vm.stopPrank();

        assertEq(token.allowance(owner, token.DEFAULT_TRANSFER_VALIDATOR()), type(uint256).max);
    }

    function testAllowanceUnlimitedWhenUserExplicitlyApprovesTransferValidator(address validator, address creator, address owner, bytes32 code) public {
        _sanitizeAddress(creator);
        _sanitizeAddress(owner);
        vm.assume(validator != owner);

        ITestCreatorToken token = _deployNewToken(creator);
        address[] memory exclusionList = new address[](1);
        exclusionList[0] = address(token);
        _sanitizeAddress(validator, exclusionList);

        vm.etch(validator, abi.encode(code));

        vm.prank(creator);
        token.setTransferValidator(address(validator));

        vm.prank(owner);
        token.approve(address(validator), type(uint256).max);

        assertEq(token.allowance(owner, address(validator)), type(uint256).max);
    }

    function testGetTransferValidationFunction() public virtual; 
}