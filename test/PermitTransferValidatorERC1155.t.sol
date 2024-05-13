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
import "lib/PermitC/src/Constants.sol";

contract PermitTransferValidatorTestERC1155 is TransferValidatorTest {
    
    struct PermitSignatureDetails {
        // Collection Address
        address token;
        // Token ID
        uint256 id;
        // An random value that can be used to invalidate the permit
        uint256 nonce;
        // Address permitted to transfer the tokens
        address operator;
        // Amount of tokens - For ERC721 this is always 1
        uint200 amount;
        // Expiration time of the permit
        uint48 expiration;
    }

    ERC1155CMock erc1155C;
    mapping(address => uint256) internal _accountPermitNonces;

    function setUp() public virtual override {
        super.setUp();

        erc1155C = new ERC1155CMock();
    }

    function _getAndIncrementAccountPermitNonce(address addr) internal returns(uint256 nextNonce) {
        nextNonce = _accountPermitNonces[addr]++;
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
        vm.assume(amount > 0 && amount < type(uint200).max);

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
        vm.assume(amount > 0 && amount < type(uint200).max);
        _mint1155(from, tokenId, amount);
        erc1155C.setTransferValidator(address(validator));

        vm.prank(from);
        erc1155C.setApprovalForAll(address(validator), true);

        (PermitSignatureDetails memory permit, bytes memory signedPermit) = _getPermitAndSignature(fromKey, from, origin, tokenId, amount);

        uint256 balanceOfFromBefore = erc1155C.balanceOf(from, tokenId);
        uint256 balanceOfToBefore = erc1155C.balanceOf(to, tokenId);

        vm.startPrank(caller, origin);

        bool isError = _permitTransfer(permit, from, to, signedPermit);
        assertEq(isError, expectedRevertSelector != 0x00000000);
        vm.stopPrank();

        if (expectedRevertSelector == bytes4(0x00000000)) {
            assertEq(erc1155C.balanceOf(from, tokenId), balanceOfFromBefore - amount);
            assertEq(erc1155C.balanceOf(to, tokenId), balanceOfToBefore + amount);
        } else {
            assertEq(erc1155C.balanceOf(from, tokenId), balanceOfFromBefore);
            assertEq(erc1155C.balanceOf(to, tokenId), balanceOfToBefore);
        }
    }

    function _getPermitAndSignature(
        uint256 fromKey, address from, address operator, uint256 tokenId, uint256 amount
    ) internal returns (PermitSignatureDetails memory permit, bytes memory signedPermit) {
        permit = PermitSignatureDetails({
            token: address(erc1155C),
            id: tokenId,
            amount: uint200(amount),
            nonce: _getAndIncrementAccountPermitNonce(from),
            operator: operator,
            expiration: uint48(block.timestamp + 1000)
        });

        uint256 masterNonce = validator.masterNonce(from);

        bytes32 permitDigest = ECDSA.toTypedDataHash(
            validator.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC1155,
                    permit.token,
                    permit.id,
                    permit.amount,
                    permit.nonce,
                    permit.operator,
                    permit.expiration,
                    masterNonce
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fromKey, permitDigest);
        signedPermit = abi.encodePacked(r, s, v);
    }

    function _permitTransfer(PermitSignatureDetails memory permit, address from, address to, bytes memory signedPermit) internal returns(bool isError) {
        isError = validator.permitTransferFromERC1155(permit.token, permit.id, permit.nonce, permit.amount, permit.expiration, from, to, permit.amount, signedPermit);
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


contract PermitTransferValidatorTestERC1155Initializable is PermitTransferValidatorTestERC1155 {
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