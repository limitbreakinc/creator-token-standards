// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/console.sol";
import "./mocks/ClonerMock.sol";
import "./mocks/ContractMock.sol";
import "./mocks/ERC721CMock.sol";
import "./mocks/ERC1155CMock.sol";
import "./interfaces/ITestCreatorToken.sol";
import "src/utils/TransferPolicy.sol";
import {CreatorTokenTransferValidator} from "src/utils/CreatorTokenTransferValidator.sol";
import "src/Constants.sol";
import "./utils/Events.sol";
import "./utils/Helpers.sol";
import "src/utils/EOARegistry.sol";
import "./TransferValidator.t.sol";

contract TransferValidatorTestERC1155 is TransferValidatorTest {

    ERC1155CMock erc1155C;

    function setUp() public virtual override {
        super.setUp();

        erc1155C = new ERC1155CMock();
    }

    function _mint1155(address to, uint256 tokenId, uint256 amount) internal virtual {
        erc1155C.mint(to, tokenId, amount);
    }

    function _sanitizeAccounts(
        address collection,
        address caller,
        address from,
        address to
    ) internal override returns (address sanitizedCollection, address sanitizedFrom, uint256 sanitizedFromKey) {
        (collection, from, sanitizedFromKey) = super._sanitizeAccounts(collection, caller, from, to);
        sanitizedCollection = address(erc1155C);
        sanitizedFromKey = uint256(uint160(from));
        sanitizedFrom = vm.addr(sanitizedFromKey);
    }

    function _beforeAuthorizedTransferCallsWithExpectedRevert(
        address authorizer,
        address origin,
        address operator,
        address collection,
        uint256 tokenId,
        uint256 amount,
        bytes4 expectedRevertSelector
    ) internal override {
        vm.assume(amount > 0);

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
    ) internal override {
        vm.assume(from != to);
        vm.assume(amount > 0);
        _mint1155(from, tokenId, amount);
        erc1155C.setTransferValidator(address(validator));

        if (caller != from) {
            vm.prank(from);
            erc1155C.setApprovalForAll(caller, true);
        }

        uint256 balanceOfFromBefore = erc1155C.balanceOf(from, tokenId);
        uint256 balanceOfToBefore = erc1155C.balanceOf(to, tokenId);

        vm.startPrank(caller, origin);
        
        if (expectedRevertSelector != 0x00000000) {
            vm.expectRevert(expectedRevertSelector);
        }
        erc1155C.safeTransferFrom(from, to, tokenId, amount, "");
        vm.stopPrank();

        if (expectedRevertSelector == bytes4(0x00000000)) {
            assertEq(erc1155C.balanceOf(from, tokenId), balanceOfFromBefore - amount);
            assertEq(erc1155C.balanceOf(to, tokenId), balanceOfToBefore + amount);
        } else {
            assertEq(erc1155C.balanceOf(from, tokenId), balanceOfFromBefore);
            assertEq(erc1155C.balanceOf(to, tokenId), balanceOfToBefore);
        }
    }

    function _sanitizeCode(
        bytes32 whitelistedCode,
        bytes32 blacklistedCode,
        bool expectRevert
    ) internal override returns (bytes32 sanitizedWhitelistedCode, bytes32 sanitizedBlacklistedCode) {
        if (expectRevert) {
            sanitizedWhitelistedCode = whitelistedCode;
        } else {
            sanitizedWhitelistedCode = 0x63f23a6e616000526020601CF300000000000000000000000000000000000000;
        }
        sanitizedBlacklistedCode = blacklistedCode;
    }

    // foundry cheat to exclude from test coverage
    function test() public {}
}


contract TransferValidatorTestERC1155Initializable is TransferValidatorTestERC1155 {
    ClonerMock cloner;

    ERC1155CInitializableMock public referenceTokenMock;

    function setUp() public virtual override {
        super.setUp();

        cloner = new ClonerMock();

        referenceTokenMock = new ERC1155CInitializableMock();

        bytes4[] memory initializationSelectors = new bytes4[](1);
        bytes[] memory initializationArguments = new bytes[](1);

        initializationSelectors[0] = referenceTokenMock.initializeERC1155.selector;
        initializationArguments[0] = abi.encode("testuri.com");

        erc1155C = ERC1155CMock(
            cloner.cloneContract(
                address(referenceTokenMock), address(this), initializationSelectors, initializationArguments
            )
        );
    }

    // foundry cheat to exclude from test coverage
    function testA() public {}
}