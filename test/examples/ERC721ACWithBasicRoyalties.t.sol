// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../CreatorTokenNonfungible.t.sol";
import "src/examples/erc721ac/ERC721ACWithBasicRoyalties.sol";

contract ERC721ACWithBasicRoyaltiesTest is CreatorTokenNonfungibleTest {
    ERC721ACWithBasicRoyalties public tokenMock;
    uint96 public constant DEFAULT_ROYALTY_FEE_NUMERATOR = 1000;
    address public constant DEFAULT_ROYALTY_FEE_RECEIVER = address(0x0b0b);
    uint256 public constant FEE_DENOMINATOR = 10000;

    function setUp() public virtual override {
        super.setUp();

        tokenMock = new ERC721ACWithBasicRoyalties(DEFAULT_ROYALTY_FEE_RECEIVER, DEFAULT_ROYALTY_FEE_NUMERATOR, "Test", "TEST");
        vm.prank(address(tokenMock));
        validator.setTransferSecurityLevelOfCollection(address(tokenMock), 1, false, false, false);
    }

    function _deployNewToken(address creator) internal virtual override returns (ITestCreatorToken) {
        vm.prank(creator);
        return ITestCreatorToken(
            address(new ERC721ACWithBasicRoyalties(DEFAULT_ROYALTY_FEE_RECEIVER, DEFAULT_ROYALTY_FEE_NUMERATOR, "Test", "TEST"))
        );
    }

    function _mintToken(address tokenAddress, address to, uint256 quantity) internal virtual override {
        ERC721ACWithBasicRoyalties(tokenAddress).mint(to, quantity);
    }

    function _safeMintToken(address tokenAddress, address to, uint256 quantity) internal virtual {
        ERC721ACWithBasicRoyalties(tokenAddress).safeMint(to, quantity);
    }

    function testSupportedTokenInterfaces() public {
        assertEq(tokenMock.supportsInterface(type(ICreatorToken).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC721).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC721Metadata).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC165).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC2981).interfaceId), true);
    }

    function testGetTransferValidationFunction() public override {
        (bytes4 functionSignature, bool isViewFunction) = tokenMock.getTransferValidationFunction();

        assertEq(functionSignature, bytes4(keccak256("validateTransfer(address,address,address,uint256)")));
        assertEq(isViewFunction, true);
    }

    function testRevertsWhenFeeNumeratorExceedsSalesPrice(uint96 royaltyFeeNumerator) public {
        vm.assume(royaltyFeeNumerator > FEE_DENOMINATOR);
        vm.expectRevert();
        new ERC721ACWithBasicRoyalties(DEFAULT_ROYALTY_FEE_RECEIVER, royaltyFeeNumerator, "Test", "TEST");
    }

    function testRoyaltyInfoForUnmintedTokenIds(uint256 tokenId, uint256 salePrice) public {
        vm.assume(salePrice < type(uint256).max / DEFAULT_ROYALTY_FEE_NUMERATOR);

        (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
        assertEq(recipient, DEFAULT_ROYALTY_FEE_RECEIVER);
        assertEq(value, (salePrice * DEFAULT_ROYALTY_FEE_NUMERATOR) / FEE_DENOMINATOR);
    }

    function testRoyaltyInfoForMintedTokenIds(address minter, uint256 quantity, uint256 salePrice) public {
        vm.assume(quantity > 0 && quantity < 5);
        vm.assume(minter != address(0));
        vm.assume(salePrice < type(uint256).max / DEFAULT_ROYALTY_FEE_NUMERATOR);

        uint256 nextTokenId = tokenMock.totalSupply();
        uint256 lastTokenId = nextTokenId + quantity - 1;

        _mintToken(address(tokenMock), minter, quantity);

        for (uint256 tokenId = nextTokenId; tokenId <= lastTokenId; ++tokenId) {
            (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
            assertEq(recipient, DEFAULT_ROYALTY_FEE_RECEIVER);
            assertEq(value, (salePrice * DEFAULT_ROYALTY_FEE_NUMERATOR) / FEE_DENOMINATOR);
        }
    }

    function testRoyaltyInfoForMintedTokenIdsAfterTransfer(
        address minter,
        address secondaryOwner,
        uint256 quantity,
        uint256 salePrice
    ) public {
        vm.assume(quantity > 0 && quantity < 5);
        vm.assume(minter != address(0));
        vm.assume(secondaryOwner != address(0));
        vm.assume(salePrice < type(uint256).max / DEFAULT_ROYALTY_FEE_NUMERATOR);

        uint256 nextTokenId = tokenMock.totalSupply();
        uint256 lastTokenId = nextTokenId + quantity - 1;

        _mintToken(address(tokenMock), minter, quantity);

        for (uint256 tokenId = nextTokenId; tokenId <= lastTokenId; ++tokenId) {
            vm.prank(minter);
            tokenMock.transferFrom(minter, secondaryOwner, tokenId);

            (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
            assertEq(recipient, DEFAULT_ROYALTY_FEE_RECEIVER);
            assertEq(value, (salePrice * DEFAULT_ROYALTY_FEE_NUMERATOR) / FEE_DENOMINATOR);
        }
    }

    function testRoyaltyRecipientResetsToAddressZeroAfterBurns(
        address minter,
        address secondaryOwner,
        uint256 quantity,
        uint256 salePrice
    ) public {
        vm.assume(quantity > 0 && quantity < 5);
        vm.assume(minter != address(0));
        vm.assume(secondaryOwner != address(0));
        vm.assume(salePrice < type(uint256).max / DEFAULT_ROYALTY_FEE_NUMERATOR);

        uint256 nextTokenId = tokenMock.totalSupply();
        uint256 lastTokenId = nextTokenId + quantity - 1;

        _mintToken(address(tokenMock), minter, quantity);

        for (uint256 tokenId = nextTokenId; tokenId <= lastTokenId; ++tokenId) {
            vm.prank(minter);
            tokenMock.transferFrom(minter, secondaryOwner, tokenId);

            vm.prank(secondaryOwner);
            tokenMock.burn(tokenId);

            (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
            assertEq(recipient, DEFAULT_ROYALTY_FEE_RECEIVER);
            assertEq(value, (salePrice * DEFAULT_ROYALTY_FEE_NUMERATOR) / FEE_DENOMINATOR);
        }
    }

    function testRoyaltyInfoForSafeMintedTokenIds(address minter, uint256 quantity, uint256 salePrice) public {
        vm.assume(quantity > 0 && quantity < 5);
        vm.assume(minter != address(0));
        vm.assume(minter.code.length == 0);
        vm.assume(salePrice < type(uint256).max / DEFAULT_ROYALTY_FEE_NUMERATOR);

        uint256 nextTokenId = tokenMock.totalSupply() + 1;
        uint256 lastTokenId = nextTokenId + quantity - 1;

        _safeMintToken(address(tokenMock), minter, quantity);

        for (uint256 tokenId = nextTokenId; tokenId <= lastTokenId; ++tokenId) {
            (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
            assertEq(recipient, DEFAULT_ROYALTY_FEE_RECEIVER);
            assertEq(value, (salePrice * DEFAULT_ROYALTY_FEE_NUMERATOR) / FEE_DENOMINATOR);
        }
    }

    function testUpdateDefaultRoyaltyInfoForMintedTokenIds(address minter, uint256 quantity, uint256 salePrice, address newRoyaltyReceiver, uint96 newRoyaltyNumerator) public {
        vm.assume(minter != address(0));
        vm.assume(minter.code.length == 0);
        vm.assume(quantity > 0 && quantity < 5);
        vm.assume(uint256(uint160(newRoyaltyReceiver)) > 0xFF);
        vm.assume(salePrice > 0);
        vm.assume(newRoyaltyNumerator < FEE_DENOMINATOR);
        vm.assume(salePrice < type(uint256).max / DEFAULT_ROYALTY_FEE_NUMERATOR);
        if(newRoyaltyNumerator > 0) {
            vm.assume(salePrice < type(uint256).max / newRoyaltyNumerator);
        }

        uint256 nextTokenId = tokenMock.totalSupply();
        uint256 lastTokenId = nextTokenId + quantity - 1;

        _mintToken(address(tokenMock), minter, quantity);

        for (uint256 tokenId = nextTokenId; tokenId <= lastTokenId; ++tokenId) {
            (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
            assertEq(recipient, DEFAULT_ROYALTY_FEE_RECEIVER);
            assertEq(value, (salePrice * DEFAULT_ROYALTY_FEE_NUMERATOR) / FEE_DENOMINATOR);
        }

        tokenMock.setDefaultRoyalty(newRoyaltyReceiver, newRoyaltyNumerator);

        for (uint256 tokenId = nextTokenId; tokenId <= lastTokenId; ++tokenId) {
            (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
            assertEq(recipient, newRoyaltyReceiver);
            assertEq(value, (salePrice * newRoyaltyNumerator) / FEE_DENOMINATOR);
        }
    }

    function testUpdateTokenRoyaltyInfoForMintedTokenIds(address minter, uint256 quantity, uint256 salePrice, address newRoyaltyReceiver, uint96 newRoyaltyNumerator) public {
        vm.assume(minter != address(0));
        vm.assume(minter.code.length == 0);
        vm.assume(quantity > 0 && quantity < 5);
        vm.assume(uint256(uint160(newRoyaltyReceiver)) > 0xFF);
        vm.assume(salePrice > 0);
        vm.assume(newRoyaltyNumerator < FEE_DENOMINATOR);
        vm.assume(salePrice < type(uint256).max / DEFAULT_ROYALTY_FEE_NUMERATOR);
        if(newRoyaltyNumerator > 0) {
            vm.assume(salePrice < type(uint256).max / newRoyaltyNumerator);
        }

        uint256 nextTokenId = tokenMock.totalSupply();
        uint256 lastTokenId = nextTokenId + quantity - 1;

        _mintToken(address(tokenMock), minter, quantity);

        for (uint256 tokenId = nextTokenId; tokenId <= lastTokenId; ++tokenId) {
            (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
            assertEq(recipient, DEFAULT_ROYALTY_FEE_RECEIVER);
            assertEq(value, (salePrice * DEFAULT_ROYALTY_FEE_NUMERATOR) / FEE_DENOMINATOR);

            tokenMock.setTokenRoyalty(tokenId, newRoyaltyReceiver, newRoyaltyNumerator);

            (recipient, value) = tokenMock.royaltyInfo(tokenId, salePrice);
            assertEq(recipient, newRoyaltyReceiver);
            assertEq(value, (salePrice * newRoyaltyNumerator) / FEE_DENOMINATOR);
        }
    }
}