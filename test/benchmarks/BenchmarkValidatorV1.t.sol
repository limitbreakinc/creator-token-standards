// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../mocks/OperatorMock.sol";
import "../mocks/ContractMock.sol";
import "../mocks/ERC721CMock.sol";
import "../interfaces/ITestCreatorToken.sol";
import "src/utils/TransferPolicy.sol";
import "src/utils/CreatorTokenTransferValidator.sol";

contract BenchmarkValidatorV1 is Test {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    CreatorTokenTransferValidator public validator;

    address validatorDeployer;

    ITestCreatorToken tokenLevelZero;
    ITestCreatorToken tokenLevelOne;
    ITestCreatorToken tokenLevelTwo;
    ITestCreatorToken tokenLevelThree;
    ITestCreatorToken tokenLevelFour;
    ITestCreatorToken tokenLevelFive;
    ITestCreatorToken tokenLevelSix;

    uint120 listIdWhitelist;
    uint120 listIdPermittedContractReceiver;

    address blacklistedOperator;
    address whitelistedOperator;

    OperatorMock blacklistedOperatorMock;
    OperatorMock whitelistedOperatorMock;
    OperatorMock blacklistedOperatorMock1;
    OperatorMock whitelistedOperatorMock1;
    OperatorMock blacklistedOperatorMock2;
    OperatorMock whitelistedOperatorMock2;

    function setUp() public virtual {
        validatorDeployer = vm.addr(1);
        vm.startPrank(validatorDeployer);
        validator = new CreatorTokenTransferValidator(validatorDeployer);
        vm.stopPrank();

        tokenLevelZero = _deployNewToken(address(this));
        tokenLevelOne = _deployNewToken(address(this));
        tokenLevelTwo = _deployNewToken(address(this));
        tokenLevelThree = _deployNewToken(address(this));
        tokenLevelFour = _deployNewToken(address(this));
        tokenLevelFive = _deployNewToken(address(this));
        tokenLevelSix = _deployNewToken(address(this));

        listIdWhitelist = validator.createOperatorWhitelist("whitelist");
        listIdPermittedContractReceiver = validator.createPermittedContractReceiverAllowlist("permitted");

        tokenLevelZero.setToCustomValidatorAndSecurityPolicy(address(validator), TransferSecurityLevels.Recommended, 0, 0);
        tokenLevelOne.setToCustomValidatorAndSecurityPolicy(address(validator), TransferSecurityLevels.One, listIdWhitelist, listIdPermittedContractReceiver);
        tokenLevelTwo.setToCustomValidatorAndSecurityPolicy(address(validator), TransferSecurityLevels.Two, listIdWhitelist, listIdPermittedContractReceiver);
        tokenLevelThree.setToCustomValidatorAndSecurityPolicy(address(validator), TransferSecurityLevels.Three, listIdWhitelist, listIdPermittedContractReceiver);
        tokenLevelFour.setToCustomValidatorAndSecurityPolicy(address(validator), TransferSecurityLevels.Four, listIdWhitelist, listIdPermittedContractReceiver);
        tokenLevelFive.setToCustomValidatorAndSecurityPolicy(address(validator), TransferSecurityLevels.Five, listIdWhitelist, listIdPermittedContractReceiver);
        tokenLevelSix.setToCustomValidatorAndSecurityPolicy(address(validator), TransferSecurityLevels.Six, listIdWhitelist, listIdPermittedContractReceiver);

        whitelistedOperatorMock = new OperatorMock(2);
        whitelistedOperatorMock1 = new OperatorMock(2);
        whitelistedOperatorMock2 = new OperatorMock(4);

        validator.addOperatorToWhitelist(listIdWhitelist, address(whitelistedOperatorMock1));
        validator.addOperatorToWhitelist(listIdWhitelist, address(whitelistedOperatorMock2));
        validator.addPermittedContractReceiverToAllowlist(listIdPermittedContractReceiver, address(whitelistedOperatorMock2));
    }

    function _deployNewToken(address creator) internal virtual returns (ITestCreatorToken) {
        vm.prank(creator);
        return ITestCreatorToken(address(new ERC721CMock()));
    }

    function _mintToken(address tokenAddress, address to, uint256 tokenId) internal virtual {
        ERC721CMock(tokenAddress).mint(to, tokenId);
    }

    /*************************************************************************/
    /*                               Level Zero                              */
    /*************************************************************************/

    // 5698 gas (1,000,000 runs)
    function testBenchmarkV1LevelZero(address caller, address from, address to) public {
        vm.assume(caller != address(0));
        vm.assume(from != address(0));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelZero));
        validator.applyCollectionTransferPolicy(caller, from, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(validator));

        console.log("Reads:");
        console.log("------");
        for (uint256 i = 0; i < reads.length; ++i) {
            console.logBytes32(reads[i]);
        }

        console.log("Writes:");
        console.log("-------");
        for (uint256 i = 0; i < writes.length; ++i) {
            console.logBytes32(writes[i]);
        }
    }

    /*************************************************************************/
    /*                               Level One                               */
    /*************************************************************************/

    // 10451 gas (1,000,000 runs)
    function testBenchmarkV1LevelOneOTC(address tokenOwner, address to) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        vm.prank(address(tokenLevelOne));
        validator.applyCollectionTransferPolicy(tokenOwner, tokenOwner, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(validator));

        console.log("Reads:");
        console.log("------");
        for (uint256 i = 0; i < reads.length; ++i) {
            console.logBytes32(reads[i]);
        }

        console.log("Writes:");
        console.log("-------");
        for (uint256 i = 0; i < writes.length; ++i) {
            console.logBytes32(writes[i]);
        }
    }

    // 10354 Gas
    function testBenchmarkV1LevelOneNonOTCOperatorAccountWhitelisted(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelOne));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock2), from, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(validator));

        console.log("Reads:");
        console.log("------");
        for (uint256 i = 0; i < reads.length; ++i) {
            console.logBytes32(reads[i]);
        }

        console.log("Writes:");
        console.log("-------");
        for (uint256 i = 0; i < writes.length; ++i) {
            console.logBytes32(writes[i]);
        }
    }

    /*************************************************************************/
    /*                               Level Two                             */
    /*************************************************************************/

    // 10354 gas
    function testBenchmarkV1LevelTwoOTCOwnerIsWhitelistedAccount(address to) public {
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        vm.prank(address(tokenLevelTwo));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock2), address(whitelistedOperatorMock2), to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(validator));

        console.log("Reads:");
        console.log("------");
        for (uint256 i = 0; i < reads.length; ++i) {
            console.logBytes32(reads[i]);
        }

        console.log("Writes:");
        console.log("-------");
        for (uint256 i = 0; i < writes.length; ++i) {
            console.logBytes32(writes[i]);
        }
    }

    // 10354 gas
    function testBenchmarkV1LevelTwoNonOTCOperatorIsWhitelistedAccount(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from.code.length == 0);
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelTwo));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock2), from, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(validator));

        console.log("Reads:");
        console.log("------");
        for (uint256 i = 0; i < reads.length; ++i) {
            console.logBytes32(reads[i]);
        }

        console.log("Writes:");
        console.log("-------");
        for (uint256 i = 0; i < writes.length; ++i) {
            console.logBytes32(writes[i]);
        }
    }

    /*************************************************************************/
    /*                               Level Three                              */
    /*************************************************************************/

    // 15416 gas
    function testBenchmarkV1LevelThreeOTCWhitelistedToAddress(address tokenOwner) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));

        
        vm.record();
        vm.prank(address(tokenLevelThree));
        validator.applyCollectionTransferPolicy(tokenOwner, tokenOwner, address(whitelistedOperatorMock2));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(validator));

        console.log("Reads:");
        console.log("------");
        for (uint256 i = 0; i < reads.length; ++i) {
            console.logBytes32(reads[i]);
        }

        console.log("Writes:");
        console.log("-------");
        for (uint256 i = 0; i < writes.length; ++i) {
            console.logBytes32(writes[i]);
        }
    }

    // 10530 gas
    function testBenchmarkV1LevelThreeOTCWhitelistedToHasNoCode(address tokenOwner, address to) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        vm.prank(address(tokenLevelThree));
        validator.applyCollectionTransferPolicy(tokenOwner, tokenOwner, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(validator));

        console.log("Reads:");
        console.log("------");
        for (uint256 i = 0; i < reads.length; ++i) {
            console.logBytes32(reads[i]);
        }

        console.log("Writes:");
        console.log("-------");
        for (uint256 i = 0; i < writes.length; ++i) {
            console.logBytes32(writes[i]);
        }
    }

    // 15319
    function testBenchmarkV2LevelThreeNonOTCWhitelistedToAddress(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelThree));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock1), from, address(whitelistedOperatorMock2));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(validator));

        console.log("Reads:");
        console.log("------");
        for (uint256 i = 0; i < reads.length; ++i) {
            console.logBytes32(reads[i]);
        }

        console.log("Writes:");
        console.log("-------");
        for (uint256 i = 0; i < writes.length; ++i) {
            console.logBytes32(writes[i]);
        }
    }

    // 10433
    function testBenchmarkV1LevelThreeNonOTCWhitelistedToHasNoCode(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelThree));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock2), from, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(validator));

        console.log("Reads:");
        console.log("------");
        for (uint256 i = 0; i < reads.length; ++i) {
            console.logBytes32(reads[i]);
        }

        console.log("Writes:");
        console.log("-------");
        for (uint256 i = 0; i < writes.length; ++i) {
            console.logBytes32(writes[i]);
        }
    }

    /*************************************************************************/
    /*                               Level Four                              */
    /*************************************************************************/

    // 15037 gas
    function testBenchmarkV1LevelFourOTCWhitelistedToAddress(address tokenOwner) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));

        
        vm.record();
        vm.prank(address(tokenLevelFour));
        validator.applyCollectionTransferPolicy(tokenOwner, tokenOwner, address(whitelistedOperatorMock2));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(validator));

        console.log("Reads:");
        console.log("------");
        for (uint256 i = 0; i < reads.length; ++i) {
            console.logBytes32(reads[i]);
        }

        console.log("Writes:");
        console.log("-------");
        for (uint256 i = 0; i < writes.length; ++i) {
            console.logBytes32(writes[i]);
        }
    }

    // 10651 gas
    function testBenchmarkV1LevelFourOTCWhitelistedToHasNoCode(address tokenOwner, uint160 toKey) public {
        address to = _verifyEOA(toKey);

        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        vm.prank(address(tokenLevelFour));
        validator.applyCollectionTransferPolicy(tokenOwner, tokenOwner, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(validator));

        console.log("Reads:");
        console.log("------");
        for (uint256 i = 0; i < reads.length; ++i) {
            console.logBytes32(reads[i]);
        }

        console.log("Writes:");
        console.log("-------");
        for (uint256 i = 0; i < writes.length; ++i) {
            console.logBytes32(writes[i]);
        }
    }

    // 14940 gas
    function testBenchmarkV1LevelFourNonOTCWhitelistedToAddress(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelFour));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock1), from, address(whitelistedOperatorMock2));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(validator));

        console.log("Reads:");
        console.log("------");
        for (uint256 i = 0; i < reads.length; ++i) {
            console.logBytes32(reads[i]);
        }

        console.log("Writes:");
        console.log("-------");
        for (uint256 i = 0; i < writes.length; ++i) {
            console.logBytes32(writes[i]);
        }
    }

    // 10554 gas
    function testBenchmarkV1LevelFourNonOTCWhitelistedToHasNoCode(address from, uint160 toKey) public {
        address to = _verifyEOA(toKey);

        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelFour));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock2), from, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(validator));

        console.log("Reads:");
        console.log("------");
        for (uint256 i = 0; i < reads.length; ++i) {
            console.logBytes32(reads[i]);
        }

        console.log("Writes:");
        console.log("-------");
        for (uint256 i = 0; i < writes.length; ++i) {
            console.logBytes32(writes[i]);
        }
    }

    /*************************************************************************/
    /*                               Level Five                               */
    /*************************************************************************/

    // 15319 gas
    function testBenchmarkV1LevelFiveNonOTCWhitelistedToAddress(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelFive));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock1), from, address(whitelistedOperatorMock2));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(validator));

        console.log("Reads:");
        console.log("------");
        for (uint256 i = 0; i < reads.length; ++i) {
            console.logBytes32(reads[i]);
        }

        console.log("Writes:");
        console.log("-------");
        for (uint256 i = 0; i < writes.length; ++i) {
            console.logBytes32(writes[i]);
        }
    }

    // 10433 gas
    function testBenchmarkV1LevelFiveNonOTCWhitelistedToHasNoCode(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelFive));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock2), from, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(validator));

        console.log("Reads:");
        console.log("------");
        for (uint256 i = 0; i < reads.length; ++i) {
            console.logBytes32(reads[i]);
        }

        console.log("Writes:");
        console.log("-------");
        for (uint256 i = 0; i < writes.length; ++i) {
            console.logBytes32(writes[i]);
        }
    }

    /*************************************************************************/
    /*                               Level Seven                             */
    /*************************************************************************/

    // 14940 gas
    function testBenchmarkV1LevelSixNonOTCWhitelistedToAddress(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelSix));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock1), from, address(whitelistedOperatorMock2));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(validator));

        console.log("Reads:");
        console.log("------");
        for (uint256 i = 0; i < reads.length; ++i) {
            console.logBytes32(reads[i]);
        }

        console.log("Writes:");
        console.log("-------");
        for (uint256 i = 0; i < writes.length; ++i) {
            console.logBytes32(writes[i]);
        }
    }

    // 10554 gas
    function testBenchmarkV1LevelSixNonOTCWhitelistedToHasNoCode(address from, uint160 toKey) public {
        address to = _verifyEOA(toKey);

        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelSix));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock2), from, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(validator));

        console.log("Reads:");
        console.log("------");
        for (uint256 i = 0; i < reads.length; ++i) {
            console.logBytes32(reads[i]);
        }

        console.log("Writes:");
        console.log("-------");
        for (uint256 i = 0; i < writes.length; ++i) {
            console.logBytes32(writes[i]);
        }
    }


    function _verifyEOA(uint160 toKey) internal returns (address to) {
        vm.assume(toKey > 0 && toKey < type(uint160).max);
        to = vm.addr(toKey);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(toKey, ECDSA.toEthSignedMessageHash(bytes(validator.MESSAGE_TO_SIGN())));
        vm.prank(to);
        validator.verifySignatureVRS(v, r, s);
    }
}