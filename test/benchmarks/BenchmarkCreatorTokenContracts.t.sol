// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../mocks/OperatorMock.sol";
import "../mocks/ContractMock.sol";
import "../mocks/ERC721CMock.sol";
import "../interfaces/ITestCreatorToken.sol";
import "src/utils/TransferPolicy.sol";
import {CreatorTokenTransferValidator} from "src/utils/CreatorTokenTransferValidator.sol";
import {CreatorTokenTransferValidatorConfiguration} from "src/utils/CreatorTokenTransferValidatorConfiguration.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "src/Constants.sol";
import "src/utils/EOARegistry.sol";

// Overall Gas Efficiency:
// | Function Name                    | min             | avg   | median | max   |
// | applyCollectionTransferPolicy    | 3240            | 9460  | 9259   | 17602 |
// | isTransferAllowed                | 6991            | 15065 | 15114  | 23457 |
// | isTransferAllowed                | 6799            | 14873 | 14922  | 23265 |
// | isTransferAllowed                | 6800            | 14874 | 14923  | 23266 |
// | isTransferAllowed                | 6900            | 14974 | 15023  | 23366 |
// | isTransferAllowed                | 6886            | 14960 | 15009  | 23352 |
// | isTransferAllowed                | 6865            | 14939 | 14988  | 23331 |

contract BenchmarkCreatorTokenContracts is Test {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    EOARegistry public eoaRegistry;
    CreatorTokenTransferValidator public validator;
    CreatorTokenTransferValidatorConfiguration public validatorConfiguration;

    address validatorDeployer;

    ITestCreatorToken tokenLevelOne;
    ITestCreatorToken tokenLevelTwo;
    ITestCreatorToken tokenLevelThree;
    ITestCreatorToken tokenLevelFour;
    ITestCreatorToken tokenLevelFive;
    ITestCreatorToken tokenLevelSix;
    ITestCreatorToken tokenLevelSeven;
    ITestCreatorToken tokenLevelEight;

    uint120 listIdBlacklist;
    uint120 listIdWhitelist;

    address blacklistedOperator;
    address whitelistedOperator;
    bytes32 blacklistedCodehash;
    bytes32 whitelistedCodehash;

    OperatorMock blacklistedOperatorMock;
    OperatorMock whitelistedOperatorMock;
    OperatorMock blacklistedOperatorMock1;
    OperatorMock whitelistedOperatorMock1;
    OperatorMock blacklistedOperatorMock2;
    OperatorMock whitelistedOperatorMock2;

    function setUp() public virtual {
        eoaRegistry = new EOARegistry();

        validatorDeployer = vm.addr(1);
        vm.startPrank(validatorDeployer);
        validatorConfiguration = new CreatorTokenTransferValidatorConfiguration(validatorDeployer);
        validatorConfiguration.setNativeValueToCheckPauseState(0);
        validator = new CreatorTokenTransferValidator(validatorDeployer, address(eoaRegistry), "", "", address(validatorConfiguration));
        vm.stopPrank();

        tokenLevelOne = _deployNewToken(address(this));
        tokenLevelTwo = _deployNewToken(address(this));
        tokenLevelThree = _deployNewToken(address(this));
        tokenLevelFour = _deployNewToken(address(this));
        tokenLevelFive = _deployNewToken(address(this));
        tokenLevelSix = _deployNewToken(address(this));
        tokenLevelSeven = _deployNewToken(address(this));
        tokenLevelEight = _deployNewToken(address(this));

        tokenLevelOne.setTransferValidator(address(validator));
        tokenLevelTwo.setTransferValidator(address(validator));
        tokenLevelThree.setTransferValidator(address(validator));
        tokenLevelFour.setTransferValidator(address(validator));
        tokenLevelFive.setTransferValidator(address(validator));
        tokenLevelSix.setTransferValidator(address(validator));
        tokenLevelSeven.setTransferValidator(address(validator));
        tokenLevelEight.setTransferValidator(address(validator));

        listIdBlacklist = validator.createList("blacklist");
        listIdWhitelist = validator.createList("whitelist");

        validator.setTransferSecurityLevelOfCollection(address(tokenLevelOne), TRANSFER_SECURITY_LEVEL_ONE, false, false, false);
        validator.applyListToCollection(address(tokenLevelOne), 0);

        validator.setTransferSecurityLevelOfCollection(address(tokenLevelTwo), TRANSFER_SECURITY_LEVEL_TWO, false, false, false);
        validator.applyListToCollection(address(tokenLevelTwo), listIdBlacklist);

        validator.setTransferSecurityLevelOfCollection(address(tokenLevelThree), TRANSFER_SECURITY_LEVEL_THREE, false, false, false);
        validator.applyListToCollection(address(tokenLevelThree), listIdWhitelist);

        validator.setTransferSecurityLevelOfCollection(address(tokenLevelFour), TRANSFER_SECURITY_LEVEL_FOUR, false, false, false);
        validator.applyListToCollection(address(tokenLevelFour), listIdWhitelist);

        validator.setTransferSecurityLevelOfCollection(address(tokenLevelFive), TRANSFER_SECURITY_LEVEL_FIVE, false, false, false);
        validator.applyListToCollection(address(tokenLevelFive), listIdWhitelist);

        validator.setTransferSecurityLevelOfCollection(address(tokenLevelSix), TRANSFER_SECURITY_LEVEL_SIX, false, false, false);
        validator.applyListToCollection(address(tokenLevelSix), listIdWhitelist);

        validator.setTransferSecurityLevelOfCollection(address(tokenLevelSeven), TRANSFER_SECURITY_LEVEL_SEVEN, false, false, false);
        validator.applyListToCollection(address(tokenLevelSeven), listIdWhitelist);

        validator.setTransferSecurityLevelOfCollection(address(tokenLevelEight), TRANSFER_SECURITY_LEVEL_EIGHT, false, false, false);
        validator.applyListToCollection(address(tokenLevelEight), listIdWhitelist);

        blacklistedOperatorMock = new OperatorMock(1);
        whitelistedOperatorMock = new OperatorMock(2);
        blacklistedOperatorMock1 = new OperatorMock(1);
        whitelistedOperatorMock1 = new OperatorMock(2);
        blacklistedOperatorMock2 = new OperatorMock(3);
        whitelistedOperatorMock2 = new OperatorMock(4);

        console.logBytes32(address(blacklistedOperatorMock).codehash);
        console.logBytes32(address(whitelistedOperatorMock).codehash);
        console.logBytes32(address(blacklistedOperatorMock1).codehash);
        console.logBytes32(address(whitelistedOperatorMock1).codehash);
        console.logBytes32(address(blacklistedOperatorMock2).codehash);
        console.logBytes32(address(whitelistedOperatorMock2).codehash);

        address[] memory blacklistedAccounts = new address[](1);
        blacklistedAccounts[0] = address(blacklistedOperatorMock2);

        bytes32[] memory blacklistedCodehashes = new bytes32[](1);
        blacklistedCodehashes[0] = address(blacklistedOperatorMock).codehash;

        validator.addAccountsToBlacklist(listIdBlacklist, blacklistedAccounts);
        validator.addCodeHashesToBlacklist(listIdBlacklist, blacklistedCodehashes);

        address[] memory whitelistedAccounts = new address[](1);
        whitelistedAccounts[0] = address(whitelistedOperatorMock2);

        bytes32[] memory whitelistedCodehashes = new bytes32[](1);
        whitelistedCodehashes[0] = address(whitelistedOperatorMock).codehash;

        validator.addAccountsToWhitelist(listIdWhitelist, whitelistedAccounts);
        validator.addCodeHashesToWhitelist(listIdWhitelist, whitelistedCodehashes);
    }

    function _deployNewToken(address creator) internal virtual returns (ITestCreatorToken) {
        vm.prank(creator);
        return ITestCreatorToken(address(new ERC721CMock()));
    }

    function _mintToken(address tokenAddress, address to, uint256 tokenId) internal virtual {
        ERC721CMock(tokenAddress).mint(to, tokenId);
    }

    /*************************************************************************/
    /*                               Level One                              */
    /*************************************************************************/

    // 3313 gas (1 SLOAD)
    function testBenchmarkTokenLevelOne(address caller, address from, address to) public {
        vm.assume(caller != address(0));
        vm.assume(caller != address(blacklistedOperatorMock));
        vm.assume(caller != address(blacklistedOperatorMock1));
        vm.assume(caller != address(blacklistedOperatorMock2));
        vm.assume(from != address(0));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelOne));
        validator.validateTransfer(caller, from, to);
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
    /*                               Level Two                               */
    /*************************************************************************/

    // 3262 gas (1 SLOAD)
    function testBenchmarkTokenLevelTwoOTC(address tokenOwner, address to) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(blacklistedOperatorMock));
        vm.assume(tokenOwner != address(blacklistedOperatorMock1));
        vm.assume(tokenOwner != address(blacklistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        vm.prank(address(tokenLevelTwo));
        validator.validateTransfer(tokenOwner, tokenOwner, to);
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

    // 10375 gas (3 SLOADS)
    function testBenchmarkTokenLevelTwoNonOTC(address caller, address from, address to) public {
        vm.assume(caller != address(0));
        vm.assume(caller != address(blacklistedOperatorMock));
        vm.assume(caller != address(blacklistedOperatorMock1));
        vm.assume(caller != address(blacklistedOperatorMock2));
        vm.assume(from != address(0));
        vm.assume(from != caller);
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        vm.record();
        vm.prank(address(tokenLevelTwo));
        validator.validateTransfer(caller, from, to);
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
    /*                               Level Three                               */
    /*************************************************************************/

    // 3311 gas (1 SLOAD)
    function testBenchmarkTokenLevelThreeOTC(address tokenOwner, address to) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        vm.prank(address(tokenLevelThree));
        validator.validateTransfer(tokenOwner, tokenOwner, to);
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

    // 5567 Gas (2 SLOADS)
    function testBenchmarkTokenLevelThreeNonOTCOperatorAccountWhitelisted(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelThree));
        validator.validateTransfer(address(whitelistedOperatorMock2), from, to);
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

    // 10374 gas (3 SLOADS)
    function testBenchmarkTokenLevelThreeNonOTCOperatorCodeHashWhitelisted(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelThree));
        validator.validateTransfer(address(whitelistedOperatorMock1), from, to);
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
    /*                               Level Four                             */
    /*************************************************************************/

    // 5724 gas (2 SLOADS)
    function testBenchmarkTokenLevelFourOTCOwnerIsWhitelistedAccount(address to) public {
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        vm.prank(address(tokenLevelFour));
        validator.validateTransfer(address(whitelistedOperatorMock2), address(whitelistedOperatorMock2), to);
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

    // 10746 gas (4 SLOADS, 1 DUP)
    function testBenchmarkTokenLevelFourOTCOwnerIsWhitelistedCodehash(address to) public {
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        vm.prank(address(tokenLevelFour));
        validator.validateTransfer(address(whitelistedOperatorMock1), address(whitelistedOperatorMock1), to);
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

    // 5676 gas (2 SLOADS)
    function testBenchmarkTokenLevelFourNonOTCOperatorIsWhitelistedAccount(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from.code.length == 0);
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelFour));
        validator.validateTransfer(address(whitelistedOperatorMock2), from, to);
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

    // 7880 gas (3 SLOADS)
    function testBenchmarkTokenLevelFourNonOTCOwnerIsWhitelistedAccount(address caller, address to) public {
        vm.assume(caller != address(0));
        vm.assume(caller.code.length == 0);
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelFour));
        validator.validateTransfer(caller, address(whitelistedOperatorMock2), to);
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

    // 12698 gas (4 SLOADS)
    function testBenchmarkTokenLevelFourNonOTCOperatorIsWhitelistedCodeHash(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from.code.length == 0);
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelFour));
        validator.validateTransfer(address(whitelistedOperatorMock1), from, to);
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

    // 15002 gas (5 SLOADS)
    function testBenchmarkTokenLevelFourNonOTCOwnerIsWhitelistedCodeHash(address caller, address to) public {
        vm.assume(caller != address(0));
        vm.assume(caller.code.length == 0);
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelFour));
        validator.validateTransfer(caller, address(whitelistedOperatorMock1), to);
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
    /*                               Level Five                              */
    /*************************************************************************/

    // 8200 gas (2 SLOADS)
    function testBenchmarkTokenLevelFiveOTCWhitelistedToAddress(address tokenOwner) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));

        
        vm.record();
        vm.prank(address(tokenLevelFive));
        validator.validateTransfer(tokenOwner, tokenOwner, address(whitelistedOperatorMock2));
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

    // 10503 gas (3 SLOADS)
    function testBenchmarkTokenLevelFiveOTCWhitelistedToCodeHash(address tokenOwner) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));

        
        vm.record();
        vm.prank(address(tokenLevelFive));
        validator.validateTransfer(tokenOwner, tokenOwner, address(whitelistedOperatorMock1));
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

    // 3497 gas (1 SLOAD)
    function testBenchmarkTokenLevelFiveOTCWhitelistedToHasNoCode(address tokenOwner, address to) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        vm.prank(address(tokenLevelFive));
        validator.validateTransfer(tokenOwner, tokenOwner, to);
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

    // 15263 gas (4 SLOADS)
    function testBenchmarkTokenLevelFiveNonOTCWhitelistedToAddress(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelFive));
        validator.validateTransfer(address(whitelistedOperatorMock1), from, address(whitelistedOperatorMock2));
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

    // 12759 (4 SLOADS)
    function testBenchmarkTokenLevelFiveNonOTCWhitelistedToCodeHash(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelFive));
        validator.validateTransfer(address(whitelistedOperatorMock2), from, address(whitelistedOperatorMock1));
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

    // 5753 (2 SLOADS)
    function testBenchmarkTokenLevelFiveNonOTCWhitelistedToHasNoCode(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelFive));
        validator.validateTransfer(address(whitelistedOperatorMock2), from, to);
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
    /*                               Level Six                              */
    /*************************************************************************/

    // 7861 gas (3 SLOADS)
    function testBenchmarkTokenLevelSixOTCWhitelistedToAddress(address tokenOwner) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));

        
        vm.record();
        vm.prank(address(tokenLevelSix));
        validator.validateTransfer(tokenOwner, tokenOwner, address(whitelistedOperatorMock2));
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

    // 12664 gas (4 SLOADS)
    function testBenchmarkTokenLevelSixOTCWhitelistedToCodeHash(address tokenOwner) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));

        
        vm.record();
        vm.prank(address(tokenLevelSix));
        validator.validateTransfer(tokenOwner, tokenOwner, address(whitelistedOperatorMock1));
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

    // 3658 gas (2 SLOADS)
    function testBenchmarkTokenLevelSixOTCWhitelistedToHasNoCode(address tokenOwner, uint160 toKey) public {
        address to = _verifyEOA(toKey);

        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        vm.prank(address(tokenLevelSix));
        validator.validateTransfer(tokenOwner, tokenOwner, to);
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

    // 14924 gas (5 SLOADS)
    function testBenchmarkTokenLevelSixNonOTCWhitelistedToAddress(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelSix));
        validator.validateTransfer(address(whitelistedOperatorMock1), from, address(whitelistedOperatorMock2));
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

    // 14920 (5 SLOADS)
    function testBenchmarkTokenLevelSixNonOTCWhitelistedToCodeHash(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelSix));
        validator.validateTransfer(address(whitelistedOperatorMock2), from, address(whitelistedOperatorMock1));
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

    // 5914 gas (3 SLOADS)
    function testBenchmarkTokenLevelSixNonOTCWhitelistedToHasNoCode(address from, uint160 toKey) public {
        address to = _verifyEOA(toKey);

        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelSix));
        validator.validateTransfer(address(whitelistedOperatorMock2), from, to);
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
    /*                               Level Seven                               */
    /*************************************************************************/

    // 17636 gas (5 SLOADS)
    function testBenchmarkTokenLevelSevenNonOTCWhitelistedToAddress(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelSeven));
        validator.validateTransfer(address(whitelistedOperatorMock1), from, address(whitelistedOperatorMock2));
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

    // 12917 gas (4 SLOADS)
    function testBenchmarkTokenLevelSevenNonOTCWhitelistedToCodeHash(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelSeven));
        validator.validateTransfer(address(whitelistedOperatorMock2), from, address(whitelistedOperatorMock1));
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

    // 5911 gas (2 SLOADS)
    function testBenchmarkTokenLevelSevenNonOTCWhitelistedToHasNoCode(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelSeven));
        validator.validateTransfer(address(whitelistedOperatorMock2), from, to);
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
    /*                               Level Eight                             */
    /*************************************************************************/

    // 17249 gas (6 SLOADS)
    function testBenchmarkTokenLevelEightNonOTCWhitelistedToAddress(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelEight));
        validator.validateTransfer(address(whitelistedOperatorMock1), from, address(whitelistedOperatorMock2));
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

    // 15030 gas (5 SLOADS)
    function testBenchmarkTokenLevelEightNonOTCWhitelistedToCodeHash(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelEight));
        validator.validateTransfer(address(whitelistedOperatorMock2), from, address(whitelistedOperatorMock1));
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

    // 6024 gas (3 SLOADS)
    function testBenchmarkTokenLevelEightNonOTCWhitelistedToHasNoCode(address from, uint160 toKey) public {
        address to = _verifyEOA(toKey);

        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelEight));
        validator.validateTransfer(address(whitelistedOperatorMock2), from, to);
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
        toKey = uint160(bound(toKey, 1, type(uint160).max));
        to = vm.addr(toKey);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(toKey, ECDSA.toEthSignedMessageHash(bytes(eoaRegistry.MESSAGE_TO_SIGN())));
        vm.prank(to);
        eoaRegistry.verifySignatureVRS(v, r, s);
    }
}