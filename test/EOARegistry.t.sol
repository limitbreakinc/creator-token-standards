// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "src/utils/EOARegistry.sol";
import "src/utils/EOARegistryAccess.sol";
import "./utils/Helpers.sol";

contract EOARegistryAccessMock is EOARegistryAccess {

}

contract EOARegistryTest is Helpers {
    EOARegistry public eoaRegistry;
    EOARegistryAccessMock private eoaRegistryAccess;

    function setUp() public virtual override {
        super.setUp();

        eoaRegistry = new EOARegistry();
        eoaRegistryAccess = new EOARegistryAccessMock();
    }

    function _verifyEOA(uint160 toKey) internal returns (address to) {
        toKey = uint160(bound(toKey, 1, type(uint160).max));
        to = vm.addr(toKey);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(toKey, ECDSA.toEthSignedMessageHash(bytes(eoaRegistry.MESSAGE_TO_SIGN())));
        vm.prank(to);
        vm.expectEmit(true, true, true, true);
        emit EOARegistry.VerifiedEOASignature(to);
        eoaRegistry.verifySignatureVRS(v, r, s);
    }

    function _verifyEOABytes(uint160 toKey) internal returns (address to) {
        toKey = uint160(bound(toKey, 1, type(uint160).max));
        to = vm.addr(toKey);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(toKey, ECDSA.toEthSignedMessageHash(bytes(eoaRegistry.MESSAGE_TO_SIGN())));
        bytes memory signatureBytes = abi.encodePacked(r, s, v);
        vm.prank(to);
        vm.expectEmit(true, true, true, true);
        emit EOARegistry.VerifiedEOASignature(to);
        eoaRegistry.verifySignature(signatureBytes);
    }

    function testVerifyEOA(uint160 toKey) public {
        toKey = uint160(bound(toKey, 1, type(uint160).max));
        address to = vm.addr(toKey);
        vm.assume(!eoaRegistry.isVerifiedEOA(to));
        _verifyEOA(toKey);
    }

    function testVerifyEOABytes(uint160 toKey) public {
        toKey = uint160(bound(toKey, 1, type(uint160).max));
        address to = vm.addr(toKey);
        vm.assume(!eoaRegistry.isVerifiedEOA(to));
        _verifyEOABytes(toKey);
    }

    function testSupportsInterface() public {
        assertTrue(eoaRegistry.supportsInterface(type(IEOARegistry).interfaceId));
        assertTrue(eoaRegistry.supportsInterface(type(IERC165).interfaceId));
    }

    function testEOARegistryAccess() public {
        vm.expectEmit(true, true, true, true);
        emit EOARegistryAccess.EOARegistryUpdated(address(0), address(eoaRegistry));
        eoaRegistryAccess.setEOARegistry(address(eoaRegistry));

        assertEq(address(eoaRegistryAccess.getEOARegistry()), address(eoaRegistry));

        vm.expectRevert(EOARegistryAccess.InvalidEOARegistryContract.selector);
        eoaRegistryAccess.setEOARegistry(address(uint160(uint256(keccak256(abi.encode(eoaRegistry))))));
    }
}