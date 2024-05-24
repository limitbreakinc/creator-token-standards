// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./CreatorTokenNonfungible.t.sol";
import "src/token/erc721/MetadataURI.sol";

contract ERC721CTest is CreatorTokenNonfungibleTest {
    function setUp() public virtual override {
        super.setUp();
    }

    function _deployNewToken(address creator) internal virtual override returns (ITestCreatorToken) {
        vm.prank(creator);
        return ITestCreatorToken(address(new ERC721CMock()));
    }

    function _mintToken(address tokenAddress, address to, uint256 tokenId) internal virtual override {
        ERC721CMock(tokenAddress).mint(to, tokenId);
    }

    function testSupportedTokenInterfaces() public {
        ITestCreatorToken tokenMock = _deployNewToken(address(this));
        assertEq(tokenMock.supportsInterface(type(ICreatorToken).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC721).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC721Metadata).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC165).interfaceId), true);
    }

    function testGetTransferValidationFunction() public override {
        ITestCreatorToken tokenMock = _deployNewToken(address(this));
        (bytes4 functionSignature, bool isViewFunction) = tokenMock.getTransferValidationFunction();

        assertEq(functionSignature, bytes4(keccak256("validateTransfer(address,address,address,uint256)")));
        assertEq(isViewFunction, true);
    }

    function testNameAndSymbol() public {
        ERC721CMock _tokenMock = ERC721CMock(address(_deployNewToken(address(this))));

        assertEq(_tokenMock.name(), "ERC-721C Mock");
        assertEq(_tokenMock.symbol(), "MOCK");
    }

    function testTransferValidatorTokenTypeIsSet() public {
        ITestCreatorToken tokenMock = _deployNewToken(address(this));
        CollectionSecurityPolicyV3 memory securityPolicy = validator.getCollectionSecurityPolicy(address(tokenMock));
        assertEq(securityPolicy.tokenType, TOKEN_TYPE_ERC721);
    }
}


contract ERC721CInitializableTest is CreatorTokenNonfungibleTest {
    ClonerMock cloner;

    ERC721CInitializableMock public tokenMock;
    ERC721CInitializableMock public referenceTokenMock;

    function setUp() public virtual override {
        super.setUp();

        cloner = new ClonerMock();

        referenceTokenMock = new ERC721CInitializableMock();

        bytes4[] memory initializationSelectors = new bytes4[](1);
        bytes[] memory initializationArguments = new bytes[](1);

        initializationSelectors[0] = referenceTokenMock.initializeERC721.selector;
        initializationArguments[0] = abi.encode("Test", "TST");

        tokenMock = ERC721CInitializableMock(
            cloner.cloneContract(
                address(referenceTokenMock), address(this), initializationSelectors, initializationArguments
            )
        );

        //TODO: tokenMock.setToCustomValidatorAndSecurityPolicy(address(validator), TransferSecurityLevels.Two, 0);
    }

    function _deployNewToken(address creator) internal virtual override returns (ITestCreatorToken) {
        bytes4[] memory initializationSelectors = new bytes4[](1);
        bytes[] memory initializationArguments = new bytes[](1);

        initializationSelectors[0] = referenceTokenMock.initializeERC721.selector;
        initializationArguments[0] = abi.encode("Test", "TST");

        console.log(address(referenceTokenMock));
        return ITestCreatorToken(
            cloner.cloneContract(address(referenceTokenMock), creator, initializationSelectors, initializationArguments)
        );
    }

    function _mintToken(address tokenAddress, address to, uint256 tokenId) internal virtual override {
        ERC721CInitializableMock(tokenAddress).mint(to, tokenId);
    }

    function testSupportedTokenInterfaces() public {
        assertEq(tokenMock.supportsInterface(type(ICreatorToken).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC721).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC721Metadata).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC165).interfaceId), true);
    }

    function testInitializeAlreadyInitialized(string memory badName, string memory badSymbol) public {
        vm.expectRevert(ERC721OpenZeppelinInitializable.ERC721OpenZeppelinInitializable__AlreadyInitializedERC721.selector);
        tokenMock.initializeERC721(badName, badSymbol);
    }

    function testRevertsWhenInitializingOwnerAgain(address badOwner) public {
        vm.expectRevert(OwnableInitializable.InitializableOwnable__OwnerAlreadyInitialized.selector);
        tokenMock.initializeOwner(badOwner);
    }

    function testGetTransferValidationFunction() public override {
        (bytes4 functionSignature, bool isViewFunction) = tokenMock.getTransferValidationFunction();

        assertEq(functionSignature, bytes4(keccak256("validateTransfer(address,address,address,uint256)")));
        assertEq(isViewFunction, true);
    }

    function testTransferValidatorTokenTypeIsSet() public {
        ITestCreatorToken tokenMock = _deployNewToken(address(this));
        CollectionSecurityPolicyV3 memory securityPolicy = validator.getCollectionSecurityPolicy(address(tokenMock));
        assertEq(securityPolicy.tokenType, TOKEN_TYPE_ERC721);
    }
}