// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../mocks/OperatorMock.sol";
import "../mocks/ContractMock.sol";
import "../mocks/ERC721CMock.sol";
import "../interfaces/ITestCreatorToken.sol";
import "src/utils/TransferPolicy.sol";
import "src/utils/CreatorTokenTransferValidatorV2.sol";

// Overall Gas Efficiency:
// | Function Name                    | min             | avg   | median | max   |
// | applyCollectionTransferPolicy    | 3240            | 9460  | 9259   | 17602 |
// | isTransferAllowed                | 6991            | 15065 | 15114  | 23457 |
// | isTransferAllowed                | 6799            | 14873 | 14922  | 23265 |
// | isTransferAllowed                | 6800            | 14874 | 14923  | 23266 |
// | isTransferAllowed                | 6900            | 14974 | 15023  | 23366 |
// | isTransferAllowed                | 6886            | 14960 | 15009  | 23352 |
// | isTransferAllowed                | 6865            | 14939 | 14988  | 23331 |

contract BenchmarkCreatorTokenContractsV2 is Test {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    CreatorTokenTransferValidatorV2 public validator;

    address validatorDeployer;

    ITestCreatorToken tokenLevelZero;
    ITestCreatorToken tokenLevelOne;
    ITestCreatorToken tokenLevelTwo;
    ITestCreatorToken tokenLevelThree;
    ITestCreatorToken tokenLevelFour;
    ITestCreatorToken tokenLevelFive;
    ITestCreatorToken tokenLevelSix;
    ITestCreatorToken tokenLevelSeven;

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
        validatorDeployer = vm.addr(1);
        vm.startPrank(validatorDeployer);
        validator = new CreatorTokenTransferValidatorV2(validatorDeployer);
        vm.stopPrank();

        tokenLevelZero = _deployNewToken(address(this));
        tokenLevelOne = _deployNewToken(address(this));
        tokenLevelTwo = _deployNewToken(address(this));
        tokenLevelThree = _deployNewToken(address(this));
        tokenLevelFour = _deployNewToken(address(this));
        tokenLevelFive = _deployNewToken(address(this));
        tokenLevelSix = _deployNewToken(address(this));
        tokenLevelSeven = _deployNewToken(address(this));

        tokenLevelZero.setTransferValidator(address(validator));
        tokenLevelOne.setTransferValidator(address(validator));
        tokenLevelTwo.setTransferValidator(address(validator));
        tokenLevelThree.setTransferValidator(address(validator));
        tokenLevelFour.setTransferValidator(address(validator));
        tokenLevelFive.setTransferValidator(address(validator));
        tokenLevelSix.setTransferValidator(address(validator));
        tokenLevelSeven.setTransferValidator(address(validator));

        listIdBlacklist = validator.createList("blacklist");
        listIdWhitelist = validator.createList("whitelist");

        tokenLevelZero.setToCustomSecurityPolicy(TransferSecurityLevels.Zero, 0);
        tokenLevelOne.setToCustomSecurityPolicy(TransferSecurityLevels.One, listIdBlacklist);
        tokenLevelTwo.setToCustomSecurityPolicy(TransferSecurityLevels.Two, listIdWhitelist);
        tokenLevelThree.setToCustomSecurityPolicy(TransferSecurityLevels.Three, listIdWhitelist);
        tokenLevelFour.setToCustomSecurityPolicy(TransferSecurityLevels.Four, listIdWhitelist);
        tokenLevelFive.setToCustomSecurityPolicy(TransferSecurityLevels.Five, listIdWhitelist);
        tokenLevelSix.setToCustomSecurityPolicy(TransferSecurityLevels.Six, listIdWhitelist);
        tokenLevelSeven.setToCustomSecurityPolicy(TransferSecurityLevels.Seven, listIdWhitelist);

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
    /*                               Level Zero                              */
    /*************************************************************************/

    // 3313 gas (1 SLOAD)
    function testBenchmarkTokenV2LevelZero(address caller, address from, address to) public {
        vm.assume(caller != address(0));
        vm.assume(caller != address(blacklistedOperatorMock));
        vm.assume(caller != address(blacklistedOperatorMock1));
        vm.assume(caller != address(blacklistedOperatorMock2));
        vm.assume(from != address(0));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        tokenLevelZero.isTransferAllowed(caller, from, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelZero));

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

    // 3262 gas (1 SLOAD)
    function testBenchmarkTokenV2LevelOneOTC(address tokenOwner, address to) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(blacklistedOperatorMock));
        vm.assume(tokenOwner != address(blacklistedOperatorMock1));
        vm.assume(tokenOwner != address(blacklistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        tokenLevelOne.isTransferAllowed(tokenOwner, tokenOwner, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelOne));

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
    function testBenchmarkTokenV2LevelOneNonOTC(address caller, address from, address to) public {
        vm.assume(caller != address(0));
        vm.assume(caller != address(blacklistedOperatorMock));
        vm.assume(caller != address(blacklistedOperatorMock1));
        vm.assume(caller != address(blacklistedOperatorMock2));
        vm.assume(from != address(0));
        vm.assume(from != caller);
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        vm.record();
        tokenLevelOne.isTransferAllowed(caller, from, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelOne));

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

    // 3311 gas (1 SLOAD)
    function testBenchmarkTokenV2LevelTwoOTC(address tokenOwner, address to) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        tokenLevelTwo.isTransferAllowed(tokenOwner, tokenOwner, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelTwo));

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
    function testBenchmarkTokenV2LevelTwoNonOTCOperatorAccountWhitelisted(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        tokenLevelTwo.isTransferAllowed(address(whitelistedOperatorMock2), from, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelTwo));

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
    function testBenchmarkTokenV2LevelTwoNonOTCOperatorCodeHashWhitelisted(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        tokenLevelTwo.isTransferAllowed(address(whitelistedOperatorMock1), from, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelTwo));

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
    /*                               Level Three                             */
    /*************************************************************************/

    // 5724 gas (2 SLOADS)
    function testBenchmarkTokenV2LevelThreeOTCOwnerIsWhitelistedAccount(address to) public {
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        tokenLevelThree.isTransferAllowed(address(whitelistedOperatorMock2), address(whitelistedOperatorMock2), to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelThree));

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
    function testBenchmarkTokenV2LevelThreeOTCOwnerIsWhitelistedCodehash(address to) public {
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        tokenLevelThree.isTransferAllowed(address(whitelistedOperatorMock1), address(whitelistedOperatorMock1), to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelThree));

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
    function testBenchmarkTokenV2LevelThreeNonOTCOperatorIsWhitelistedAccount(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from.code.length == 0);
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        tokenLevelThree.isTransferAllowed(address(whitelistedOperatorMock2), from, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelThree));

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
    function testBenchmarkTokenV2LevelThreeNonOTCOwnerIsWhitelistedAccount(address caller, address to) public {
        vm.assume(caller != address(0));
        vm.assume(caller.code.length == 0);
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        tokenLevelThree.isTransferAllowed(caller, address(whitelistedOperatorMock2), to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelThree));

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
    function testBenchmarkTokenV2LevelThreeNonOTCOperatorIsWhitelistedCodeHash(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from.code.length == 0);
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        tokenLevelThree.isTransferAllowed(address(whitelistedOperatorMock1), from, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelThree));

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
    function testBenchmarkTokenV2LevelThreeNonOTCOwnerIsWhitelistedCodeHash(address caller, address to) public {
        vm.assume(caller != address(0));
        vm.assume(caller.code.length == 0);
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        tokenLevelThree.isTransferAllowed(caller, address(whitelistedOperatorMock1), to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelThree));

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

    // 8200 gas (2 SLOADS)
    function testBenchmarkTokenV2LevelFourOTCWhitelistedToAddress(address tokenOwner) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));

        
        vm.record();
        tokenLevelFour.isTransferAllowed(tokenOwner, tokenOwner, address(whitelistedOperatorMock2));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelFour));

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
    function testBenchmarkTokenV2LevelFourOTCWhitelistedToCodeHash(address tokenOwner) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));

        
        vm.record();
        tokenLevelFour.isTransferAllowed(tokenOwner, tokenOwner, address(whitelistedOperatorMock1));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelFour));

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
    function testBenchmarkTokenV2LevelFourOTCWhitelistedToHasNoCode(address tokenOwner, address to) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        tokenLevelFour.isTransferAllowed(tokenOwner, tokenOwner, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelFour));

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
    function testBenchmarkTokenV2LevelFourNonOTCWhitelistedToAddress(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        tokenLevelFour.isTransferAllowed(address(whitelistedOperatorMock1), from, address(whitelistedOperatorMock2));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelFour));

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
    function testBenchmarkTokenV2LevelFourNonOTCWhitelistedToCodeHash(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        tokenLevelFour.isTransferAllowed(address(whitelistedOperatorMock2), from, address(whitelistedOperatorMock1));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelFour));

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
    function testBenchmarkTokenV2LevelFourNonOTCWhitelistedToHasNoCode(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        tokenLevelFour.isTransferAllowed(address(whitelistedOperatorMock2), from, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelFour));

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

    // 7861 gas (3 SLOADS)
    function testBenchmarkTokenV2LevelFiveOTCWhitelistedToAddress(address tokenOwner) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));

        
        vm.record();
        tokenLevelFive.isTransferAllowed(tokenOwner, tokenOwner, address(whitelistedOperatorMock2));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelFive));

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
    function testBenchmarkTokenV2LevelFiveOTCWhitelistedToCodeHash(address tokenOwner) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));

        
        vm.record();
        tokenLevelFive.isTransferAllowed(tokenOwner, tokenOwner, address(whitelistedOperatorMock1));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelFive));

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
    function testBenchmarkTokenV2LevelFiveOTCWhitelistedToHasNoCode(address tokenOwner, uint160 toKey) public {
        address to = _verifyEOA(toKey);

        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        tokenLevelFive.isTransferAllowed(tokenOwner, tokenOwner, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelFive));

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
    function testBenchmarkTokenV2LevelFiveNonOTCWhitelistedToAddress(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        tokenLevelFive.isTransferAllowed(address(whitelistedOperatorMock1), from, address(whitelistedOperatorMock2));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelFive));

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
    function testBenchmarkTokenV2LevelFiveNonOTCWhitelistedToCodeHash(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        tokenLevelFive.isTransferAllowed(address(whitelistedOperatorMock2), from, address(whitelistedOperatorMock1));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelFive));

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
    function testBenchmarkTokenV2LevelFiveNonOTCWhitelistedToHasNoCode(address from, uint160 toKey) public {
        address to = _verifyEOA(toKey);

        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        tokenLevelFive.isTransferAllowed(address(whitelistedOperatorMock2), from, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelFive));

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
    /*                               Level Six                               */
    /*************************************************************************/

    // 17636 gas (5 SLOADS)
    function testBenchmarkTokenV2LevelSixNonOTCWhitelistedToAddress(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        tokenLevelSix.isTransferAllowed(address(whitelistedOperatorMock1), from, address(whitelistedOperatorMock2));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelSix));

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
    function testBenchmarkTokenV2LevelSixNonOTCWhitelistedToCodeHash(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        tokenLevelSix.isTransferAllowed(address(whitelistedOperatorMock2), from, address(whitelistedOperatorMock1));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelSix));

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
    function testBenchmarkTokenV2LevelSixNonOTCWhitelistedToHasNoCode(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        tokenLevelSix.isTransferAllowed(address(whitelistedOperatorMock2), from, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelSix));

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

    // 17249 gas (6 SLOADS)
    function testBenchmarkTokenV2LevelSevenNonOTCWhitelistedToAddress(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        tokenLevelSeven.isTransferAllowed(address(whitelistedOperatorMock1), from, address(whitelistedOperatorMock2));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelSeven));

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
    function testBenchmarkTokenV2LevelSevenNonOTCWhitelistedToCodeHash(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        tokenLevelSeven.isTransferAllowed(address(whitelistedOperatorMock2), from, address(whitelistedOperatorMock1));
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelSeven));

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
    function testBenchmarkTokenV2LevelSevenNonOTCWhitelistedToHasNoCode(address from, uint160 toKey) public {
        address to = _verifyEOA(toKey);

        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        tokenLevelSeven.isTransferAllowed(address(whitelistedOperatorMock2), from, to);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tokenLevelSeven));

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

//| applyCollectionTransferPolicy  | 3262            | 9487  | 9287   | 17636 | 30