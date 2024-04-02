// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/console.sol";
import "./mocks/ClonerMock.sol";
import "./mocks/ContractMock.sol";
import "./mocks/ERC721CMock.sol";
import "./mocks/ERC1155CMock.sol";
import "./interfaces/ITestCreatorToken.sol";
import "src/utils/TransferPolicy.sol";
import "src/utils/CreatorTokenTransferValidator.sol";
import "src/Constants.sol";
import "./utils/Events.sol";
import "./utils/Helpers.sol";
import "src/utils/EOARegistry.sol";
import "./TransferValidator.t.sol";
import "lib/PermitC/src/Constants.sol";

contract TransferValidatorTestERC721 is TransferValidatorTest {

    ERC721CMock erc721C;

    function setUp() public virtual override {
        super.setUp();

        erc721C = new ERC721CMock();
    }

    function _mint721(address to, uint256 tokenId) internal virtual {
        erc721C.mint(to, tokenId);
    }

    function _sanitizeAccounts(
        address collection,
        address caller,
        address from,
        address to
    ) internal override returns (address sanitizedCollection, address sanitizedFrom, uint256 sanitizedFromKey) {
        (collection, from, sanitizedFromKey) = super._sanitizeAccounts(collection, caller, from, to);
        sanitizedCollection = address(erc721C);
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
        amount = 1;

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
        amount = 1;
        _mint721(from, tokenId);
        erc721C.setTransferValidator(address(validator));

        if (caller != from) {
            vm.prank(from);
            erc721C.setApprovalForAll(caller, true);
        }

        vm.startPrank(caller, origin);

        if (expectedRevertSelector != 0x00000000) {
            vm.expectRevert(expectedRevertSelector);
        }
        erc721C.transferFrom(from, to, tokenId);
        
        vm.stopPrank();

        if (expectedRevertSelector == bytes4(0x00000000)) {
            assertEq(erc721C.ownerOf(tokenId), to);
        } else {
            assertEq(erc721C.ownerOf(tokenId), from);
        }
    }
    
}
