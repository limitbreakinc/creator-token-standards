// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "../CreatorTokenNonfungible.t.sol";
import "../mocks/AdventureMock.sol";
import "../mocks/AdventureERC721CMock.sol";
import "../mocks/ClonerMock.sol";
import "src/adventures/AdventureERC721.sol";

abstract contract AdventureHelper {
    AdventureMock adventure;

    function deployAdventure(bool questLockTokens, address adventureNFT) public {
        adventure = new AdventureMock(questLockTokens, adventureNFT);
        AdventureERC721CMock(adventureNFT).whitelistAdventure(address(adventure));
    }
}

contract ERC721CTest is CreatorTokenNonfungibleTest, AdventureHelper {
    function setUp() public virtual override {
        super.setUp();
    }

    function _deployNewToken(address creator) internal virtual override returns (ITestCreatorToken) {
        vm.prank(creator);
        return ITestCreatorToken(address(new AdventureERC721CMock()));
    }

    function _mintToken(address tokenAddress, address to, uint256 tokenId) internal virtual override {
        ITestCreatorToken(tokenAddress).mint(to, tokenId);
    }

    function testSupportedTokenInterfaces() public {
        ITestCreatorToken tokenMock = _deployNewToken(address(this));
        assertEq(tokenMock.supportsInterface(type(ICreatorToken).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC721).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC721Metadata).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC165).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IAdventurous).interfaceId), true);
    }

    function testGetTransferValidationFunction() public override {
        ITestCreatorToken tokenMock = _deployNewToken(address(this));
        (bytes4 functionSignature, bool isViewFunction) = tokenMock.getTransferValidationFunction();

        assertEq(functionSignature, bytes4(keccak256("validateTransfer(address,address,address,uint256)")));
        assertEq(isViewFunction, true);
    }

    function testAdventureLocksTokens() public {
        ITestCreatorToken tokenMock = _deployNewToken(address(this));
        deployAdventure(true, address(tokenMock));

        tokenMock.mint(address(this), 1);
        tokenMock.setAdventuresApprovedForAll(address(adventure), true);
        adventure.enterQuest(1, 1);

        vm.expectRevert(AdventureBase.AdventureERC721__AnActiveQuestIsPreventingTransfers.selector);
        tokenMock.transferFrom(address(this), address(0xdeadbeef), 1);
    }
}

contract AdventureERC721CInitializableTest is AdventureHelper, CreatorTokenNonfungibleTest {
    ClonerMock cloner;

    AdventureERC721CInitializableMock public tokenMock;
    AdventureERC721CInitializableMock public referenceTokenMock;

    function setUp() public virtual override {
        super.setUp();

        cloner = new ClonerMock();

        referenceTokenMock = new AdventureERC721CInitializableMock();

        bytes4[] memory initializationSelectors = new bytes4[](2);
        bytes[] memory initializationArguments = new bytes[](2);

        initializationSelectors[0] = referenceTokenMock.initializeERC721.selector;
        initializationArguments[0] = abi.encode("Test", "TST");

        initializationSelectors[1] = referenceTokenMock.initializeMaxSimultaneousQuestsAndTransferType.selector;
        initializationArguments[1] = abi.encode(100);

        tokenMock = AdventureERC721CInitializableMock(
            cloner.cloneContract(
                address(referenceTokenMock), address(this), initializationSelectors, initializationArguments
            )
        );
        //TODO: tokenMock.setToCustomValidatorAndSecurityPolicy(address(validator), TransferSecurityLevels.Two, 0);
    }

    function _deployNewToken(address creator) internal virtual override returns (ITestCreatorToken) {
        bytes4[] memory initializationSelectors = new bytes4[](2);
        bytes[] memory initializationArguments = new bytes[](2);

        initializationSelectors[0] = referenceTokenMock.initializeERC721.selector;
        initializationArguments[0] = abi.encode("Test", "TST");

        initializationSelectors[1] = referenceTokenMock.initializeMaxSimultaneousQuestsAndTransferType.selector;
        initializationArguments[1] = abi.encode(100);

        vm.prank(creator);
        return ITestCreatorToken(
            cloner.cloneContract(address(referenceTokenMock), creator, initializationSelectors, initializationArguments)
        );
    }

    function _mintToken(address tokenAddress, address to, uint256 tokenId) internal virtual override {
        AdventureERC721CInitializableMock(tokenAddress).mint(to, tokenId);
    }

    function testSupportedTokenInterfaces() public {
        assertEq(tokenMock.supportsInterface(type(ICreatorToken).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC721).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IAdventurous).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC721Metadata).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC165).interfaceId), true);
    }

    function testGetTransferValidationFunction() public override {
        (bytes4 functionSignature, bool isViewFunction) = tokenMock.getTransferValidationFunction();

        assertEq(functionSignature, bytes4(keccak256("validateTransfer(address,address,address,uint256)")));
        assertEq(isViewFunction, true);
    }

    function testAdventureLocksTokens() public {
        deployAdventure(true, address(tokenMock));

        tokenMock.mint(address(this), 1);
        tokenMock.setAdventuresApprovedForAll(address(adventure), true);
        adventure.enterQuest(1, 1);

        vm.expectRevert(AdventureBase.AdventureERC721__AnActiveQuestIsPreventingTransfers.selector);
        tokenMock.transferFrom(address(this), address(0xdeadbeef), 1);
    }

    function testRevertsWhenInitializingOwnerAgain(address badOwner) public {
        vm.expectRevert(OwnableInitializable.InitializableOwnable__OwnerAlreadyInitialized.selector);
        tokenMock.initializeOwner(badOwner);
    }
}