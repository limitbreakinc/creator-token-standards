// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../mocks/OperatorMock.sol";
import "../mocks/ContractMock.sol";
import "../mocks/ERC721CMock.sol";
import "../interfaces/ITestCreatorToken.sol";
import "src/utils/TransferPolicy.sol";
import "src/utils/CreatorTokenTransferValidatorV3.sol";

// Overall Gas Efficiency:
// | Function Name                    | min             | avg   | median | max   |
// | applyCollectionTransferPolicy    | 3217            | 9479  | 9345   | 17722 |

contract BenchmarkValidatorV3 is Test {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    CreatorTokenTransferValidatorV3 public validator;

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
        validatorDeployer = vm.addr(1);
        vm.startPrank(validatorDeployer);
        validator = new CreatorTokenTransferValidatorV3(validatorDeployer, "Permit-C", "3");
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

        validator.setTransferSecurityLevelOfCollection(address(tokenLevelOne), TRANSFER_SECURITY_LEVEL_ONE, true);
        validator.setTransferSecurityLevelOfCollection(address(tokenLevelTwo), TRANSFER_SECURITY_LEVEL_TWO, true);
        validator.setTransferSecurityLevelOfCollection(address(tokenLevelThree), TRANSFER_SECURITY_LEVEL_THREE, true);
        validator.setTransferSecurityLevelOfCollection(address(tokenLevelFour), TRANSFER_SECURITY_LEVEL_FOUR, true);
        validator.setTransferSecurityLevelOfCollection(address(tokenLevelFive), TRANSFER_SECURITY_LEVEL_FIVE, true);
        validator.setTransferSecurityLevelOfCollection(address(tokenLevelSix), TRANSFER_SECURITY_LEVEL_SIX, true);
        validator.setTransferSecurityLevelOfCollection(address(tokenLevelSeven), TRANSFER_SECURITY_LEVEL_SEVEN, true);
        validator.setTransferSecurityLevelOfCollection(address(tokenLevelEight), TRANSFER_SECURITY_LEVEL_EIGHT, true);

        validator.applyListToCollection(address(tokenLevelOne), 0);
        validator.applyListToCollection(address(tokenLevelTwo), listIdBlacklist);
        validator.applyListToCollection(address(tokenLevelThree), listIdWhitelist);
        validator.applyListToCollection(address(tokenLevelFour), listIdWhitelist);
        validator.applyListToCollection(address(tokenLevelFive), listIdWhitelist);
        validator.applyListToCollection(address(tokenLevelSix), listIdWhitelist);
        validator.applyListToCollection(address(tokenLevelSeven), listIdWhitelist);
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

    function testV3BenchmarktokenLevelOne(address caller, address from, address to) public {
        vm.assume(caller != address(0));
        vm.assume(caller != address(blacklistedOperatorMock));
        vm.assume(caller != address(blacklistedOperatorMock1));
        vm.assume(caller != address(blacklistedOperatorMock2));
        vm.assume(from != address(0));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelOne));
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
    /*                               Level Two                               */
    /*************************************************************************/

    function testV3BenchmarktokenLevelTwoOTC(address tokenOwner, address to) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(blacklistedOperatorMock));
        vm.assume(tokenOwner != address(blacklistedOperatorMock1));
        vm.assume(tokenOwner != address(blacklistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        vm.prank(address(tokenLevelTwo));
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

    function testV3BenchmarktokenLevelTwoNonOTC(address caller, address from, address to) public {
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
    /*                               Level Three                               */
    /*************************************************************************/

    function testV3BenchmarktokenLevelThreeOTC(address tokenOwner, address to) public {
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

    function testV3BenchmarktokenLevelThreeNonOTCOperatorAccountWhitelisted(address from, address to) public {
        vm.assume(from != address(0));
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

    function testV3BenchmarktokenLevelThreeNonOTCOperatorCodeHashWhitelisted(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelThree));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock1), from, to);
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

    function testV3BenchmarktokenLevelFourOTCOwnerIsWhitelistedAccount(address to) public {
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        vm.prank(address(tokenLevelFour));
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

    function testV3BenchmarktokenLevelFourOTCOwnerIsWhitelistedCodehash(address to) public {
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        vm.prank(address(tokenLevelFour));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock1), address(whitelistedOperatorMock1), to);
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

    function testV3BenchmarktokenLevelFourNonOTCOperatorIsWhitelistedAccount(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from.code.length == 0);
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

    function testV3BenchmarktokenLevelFourNonOTCOwnerIsWhitelistedAccount(address caller, address to) public {
        vm.assume(caller != address(0));
        vm.assume(caller.code.length == 0);
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelFour));
        validator.applyCollectionTransferPolicy(caller, address(whitelistedOperatorMock2), to);
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

    function testV3BenchmarktokenLevelFourNonOTCOperatorIsWhitelistedCodeHash(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from.code.length == 0);
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelFour));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock1), from, to);
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

    function testV3BenchmarktokenLevelFourNonOTCOwnerIsWhitelistedCodeHash(address caller, address to) public {
        vm.assume(caller != address(0));
        vm.assume(caller.code.length == 0);
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelFour));
        validator.applyCollectionTransferPolicy(caller, address(whitelistedOperatorMock1), to);
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

    function testV3BenchmarktokenLevelFiveOTCWhitelistedToAddress(address tokenOwner) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));

        
        vm.record();
        vm.prank(address(tokenLevelFive));
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

    function testV3BenchmarktokenLevelFiveOTCWhitelistedToCodeHash(address tokenOwner) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));

        
        vm.record();
        vm.prank(address(tokenLevelFive));
        validator.applyCollectionTransferPolicy(tokenOwner, tokenOwner, address(whitelistedOperatorMock1));
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

    function testV3BenchmarktokenLevelFiveOTCWhitelistedToHasNoCode(address tokenOwner, address to) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        vm.prank(address(tokenLevelFive));
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

    function testV3BenchmarktokenLevelFiveNonOTCWhitelistedToAddress(address from) public {
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

    function testV3BenchmarktokenLevelFiveNonOTCWhitelistedToCodeHash(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelFive));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock2), from, address(whitelistedOperatorMock1));
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

    function testV3BenchmarktokenLevelFiveNonOTCWhitelistedToHasNoCode(address from, address to) public {
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
    /*                               Level Six                              */
    /*************************************************************************/

    function testV3BenchmarktokenLevelSixOTCWhitelistedToAddress(address tokenOwner) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));

        
        vm.record();
        vm.prank(address(tokenLevelSix));
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

    function testV3BenchmarktokenLevelSixOTCWhitelistedToCodeHash(address tokenOwner) public {
        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));

        
        vm.record();
        vm.prank(address(tokenLevelSix));
        validator.applyCollectionTransferPolicy(tokenOwner, tokenOwner, address(whitelistedOperatorMock1));
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

    function testV3BenchmarktokenLevelSixOTCWhitelistedToHasNoCode(address tokenOwner, uint160 toKey) public {
        address to = _verifyEOA(toKey);

        vm.assume(tokenOwner != address(0));
        vm.assume(tokenOwner != address(whitelistedOperatorMock));
        vm.assume(tokenOwner != address(whitelistedOperatorMock1));
        vm.assume(tokenOwner != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);

        
        vm.record();
        vm.prank(address(tokenLevelSix));
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

    function testV3BenchmarktokenLevelSixNonOTCWhitelistedToAddress(address from) public {
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

    function testV3BenchmarktokenLevelSixNonOTCWhitelistedToCodeHash(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelSix));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock2), from, address(whitelistedOperatorMock1));
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

    function testV3BenchmarktokenLevelSixNonOTCWhitelistedToHasNoCode(address from, uint160 toKey) public {
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

    /*************************************************************************/
    /*                               Level Seven                               */
    /*************************************************************************/

    function testV3BenchmarktokenLevelSevenNonOTCWhitelistedToAddress(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelSeven));
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

    function testV3BenchmarktokenLevelSevenNonOTCWhitelistedToCodeHash(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelSeven));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock2), from, address(whitelistedOperatorMock1));
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

    function testV3BenchmarktokenLevelSevenNonOTCWhitelistedToHasNoCode(address from, address to) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelSeven));
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
    /*                               Level Eight                             */
    /*************************************************************************/

    function testV3BenchmarktokenLevelEightNonOTCWhitelistedToAddress(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelEight));
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

    function testV3BenchmarktokenLevelEightNonOTCWhitelistedToCodeHash(address from) public {
        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        
        vm.record();
        vm.prank(address(tokenLevelEight));
        validator.applyCollectionTransferPolicy(address(whitelistedOperatorMock2), from, address(whitelistedOperatorMock1));
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

    function testV3BenchmarktokenLevelEightNonOTCWhitelistedToHasNoCode(address from, uint160 toKey) public {
        address to = _verifyEOA(toKey);

        vm.assume(from != address(0));
        vm.assume(from != address(whitelistedOperatorMock));
        vm.assume(from != address(whitelistedOperatorMock1));
        vm.assume(from != address(whitelistedOperatorMock2));
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);
        
        vm.record();
        vm.prank(address(tokenLevelEight));
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