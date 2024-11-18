// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/console.sol";
import "./mocks/ClonerMock.sol";
import "./mocks/ContractMock.sol";
import "./mocks/ERC721CMock.sol";
import "./interfaces/ITestCreatorToken.sol";
import "src/utils/TransferPolicy.sol";
import {CreatorTokenTransferValidator} from "src/utils/CreatorTokenTransferValidator.sol";
import {CreatorTokenTransferValidatorConfiguration} from "src/utils/CreatorTokenTransferValidatorConfiguration.sol";
import "src/Constants.sol";
import "./utils/Events.sol";
import "./utils/Helpers.sol";
import "src/utils/EOARegistry.sol";

abstract contract CreatorTokenTest is Events, Helpers {
    EOARegistry public eoaRegistry;
    CreatorTokenTransferValidator public validator;
    CreatorTokenTransferValidatorConfiguration public validatorConfiguration;

    function setUp() public virtual override {
        super.setUp();

        eoaRegistry = new EOARegistry();
        validatorConfiguration = new CreatorTokenTransferValidatorConfiguration(address(this));
        validatorConfiguration.setNativeValueToCheckPauseState(0);
        validator = new CreatorTokenTransferValidator(address(this), address(eoaRegistry), "", "", address(validatorConfiguration));

        uint256 validatorCodeSize;
        assembly {
            validatorCodeSize := extcodesize(sload(validator.slot))
        }
        bytes memory validatorDeployedBytecode = new bytes(validatorCodeSize);
        assembly {
            extcodecopy(sload(validator.slot), add(validatorDeployedBytecode, 0x20), 0x00, validatorCodeSize)
        }
        vm.etch(0x721C002B0059009a671D00aD1700c9748146cd1B, validatorDeployedBytecode);
        validator = CreatorTokenTransferValidator(0x721C002B0059009a671D00aD1700c9748146cd1B);
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

    function testGetTransferValidatorReturnsTransferValidatorAddressBeforeValidatorIsSet(address creator) public {
        vm.assume(creator != address(0));

        _sanitizeAddress(creator);
        ITestCreatorToken token = _deployNewToken(creator);
        assertEq(address(token.getTransferValidator()), token.DEFAULT_TRANSFER_VALIDATOR());
    }

    function testRevertsWhenSetTransferValidatorCalledWithContractThatHasCodeLengthZero(address creator, address validator) public {
        _sanitizeAddress(creator);

        ITestCreatorToken token = _deployNewToken(creator);
        address[] memory exclusionList = new address[](1);
        exclusionList[0] = address(token);
        _sanitizeAddress(validator, exclusionList);

        vm.startPrank(creator);
        vm.expectRevert(CreatorTokenBase.CreatorTokenBase__InvalidTransferValidatorContract.selector);
        token.setTransferValidator(validator);
        vm.stopPrank();
    }

    function testAllowsAnyAddressToBeSetAsValidatorIfItHasCode(address creator, address validator, bytes32 code) public {
        _sanitizeAddress(creator);

        ITestCreatorToken token = _deployNewToken(creator);
        address[] memory exclusionList = new address[](1);
        exclusionList[0] = address(token);
        _sanitizeAddress(validator, exclusionList);

        vm.etch(validator, abi.encode(code));

        vm.startPrank(creator);
        token.setTransferValidator(validator);
        vm.stopPrank();

        assertEq(token.getTransferValidator(), validator);
    }

    function testAllowsValidatorToBeSetBackToZeroAddress(address creator, address validator, bytes32 code) public {
        _sanitizeAddress(creator);

        ITestCreatorToken token = _deployNewToken(creator);
        address[] memory exclusionList = new address[](1);
        exclusionList[0] = address(token);
        _sanitizeAddress(validator, exclusionList);

        vm.etch(validator, abi.encode(code));

        vm.startPrank(creator);
        token.setTransferValidator(validator);
        token.setTransferValidator(address(0));
        vm.stopPrank();

        assertEq(address(token.getTransferValidator()), address(0));
    }
}
