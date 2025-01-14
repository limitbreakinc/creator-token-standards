// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../CreatorTokenNonfungible.t.sol";
import "src/examples/erc721ac/ERC721ACWithImmutableMinterRoyalties.sol";

contract ERC721ACWithImmutableMinterRoyaltiesTest is CreatorTokenNonfungibleTest {
    ERC721ACWithImmutableMinterRoyalties public tokenMock;
    uint256 public constant DEFAULT_ROYALTY_FEE_NUMERATOR = 1000;

    function setUp() public virtual override {
        super.setUp();

        tokenMock = new ERC721ACWithImmutableMinterRoyalties(DEFAULT_ROYALTY_FEE_NUMERATOR, "Test", "TEST");
        //TODO: tokenMock.setToCustomValidatorAndSecurityPolicy(address(validator), TransferSecurityLevels.One, 1, 0);
    }

    function _deployNewToken(address creator) internal virtual override returns (ITestCreatorToken) {
        vm.prank(creator);
        return ITestCreatorToken(
            address(new ERC721ACWithImmutableMinterRoyalties(DEFAULT_ROYALTY_FEE_NUMERATOR, "Test", "TEST"))
        );
    }

    function _mintToken(address tokenAddress, address to, uint256 quantity) internal virtual override {
        ERC721ACWithImmutableMinterRoyalties(tokenAddress).mint(to, quantity);
    }

    function _safeMintToken(address tokenAddress, address to, uint256 quantity) internal {
        ERC721ACWithImmutableMinterRoyalties(tokenAddress).safeMint(to, quantity);
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

    function testRevertsWhenFeeNumeratorExceedsSalesPrice(uint256 royaltyFeeNumerator) public {
        vm.assume(royaltyFeeNumerator > tokenMock.FEE_DENOMINATOR());
        vm.expectRevert(ImmutableMinterRoyaltiesBase.ImmutableMinterRoyalties__RoyaltyFeeWillExceedSalePrice.selector);
        new ERC721ACWithImmutableMinterRoyalties(royaltyFeeNumerator, "Test", "TEST");
    }

    function testRoyaltyInfoForUnmintedTokenIds(uint256 tokenId, uint256 salePrice) public {
        vm.assume(salePrice < type(uint256).max / tokenMock.royaltyFeeNumerator());

        (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
        assertEq(recipient, address(0));
        assertEq(value, (salePrice * tokenMock.royaltyFeeNumerator()) / tokenMock.FEE_DENOMINATOR());
    }

    function testRevertsWhenMintingToZeroAddress(uint256 quantity) public {
        vm.assume(quantity > 0 && quantity < 5);

        uint256 nextTokenId = tokenMock.totalSupply() + 1;
        uint256 lastTokenId = nextTokenId + quantity - 1;

        vm.expectRevert(ImmutableMinterRoyaltiesBase.ImmutableMinterRoyalties__MinterCannotBeZeroAddress.selector);
        _mintToken(address(tokenMock), address(0), quantity);
    }

    function testRoyaltyInfoForMintedTokenIds(address minter, uint256 quantity, uint256 salePrice) public {
        vm.assume(quantity > 0 && quantity < 5);
        vm.assume(minter != address(0));
        vm.assume(salePrice < type(uint256).max / tokenMock.royaltyFeeNumerator());

        uint256 nextTokenId = tokenMock.totalSupply() + 1;
        uint256 lastTokenId = nextTokenId + quantity - 1;

        _mintToken(address(tokenMock), minter, quantity);

        for (uint256 tokenId = nextTokenId; tokenId <= lastTokenId; ++tokenId) {
            (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
            assertEq(recipient, minter);
            assertEq(value, (salePrice * tokenMock.royaltyFeeNumerator()) / tokenMock.FEE_DENOMINATOR());
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
        vm.assume(salePrice < type(uint256).max / tokenMock.royaltyFeeNumerator());

        uint256 nextTokenId = tokenMock.totalSupply() + 1;
        uint256 lastTokenId = nextTokenId + quantity - 1;

        _mintToken(address(tokenMock), minter, quantity);

        for (uint256 tokenId = nextTokenId; tokenId <= lastTokenId; ++tokenId) {
            vm.prank(minter);
            tokenMock.transferFrom(minter, secondaryOwner, tokenId);

            (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
            assertEq(recipient, minter);
            assertEq(value, (salePrice * tokenMock.royaltyFeeNumerator()) / tokenMock.FEE_DENOMINATOR());
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
        vm.assume(salePrice < type(uint256).max / tokenMock.royaltyFeeNumerator());

        uint256 nextTokenId = tokenMock.totalSupply() + 1;
        uint256 lastTokenId = nextTokenId + quantity - 1;

        _mintToken(address(tokenMock), minter, quantity);

        for (uint256 tokenId = nextTokenId; tokenId <= lastTokenId; ++tokenId) {
            vm.prank(minter);
            tokenMock.transferFrom(minter, secondaryOwner, tokenId);

            vm.prank(secondaryOwner);
            tokenMock.burn(tokenId);

            (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
            assertEq(recipient, address(0));
            assertEq(value, (salePrice * tokenMock.royaltyFeeNumerator()) / tokenMock.FEE_DENOMINATOR());
        }
    }

    function testRoyaltyInfoForSafeMintedTokenIds(address minter, uint256 quantity, uint256 salePrice) public {
        vm.assume(quantity > 0 && quantity < 5);
        vm.assume(minter != address(0));
        vm.assume(minter.code.length == 0);
        vm.assume(salePrice < type(uint256).max / tokenMock.royaltyFeeNumerator());

        uint256 nextTokenId = tokenMock.totalSupply() + 1;
        uint256 lastTokenId = nextTokenId + quantity - 1;

        _safeMintToken(address(tokenMock), minter, quantity);

        for (uint256 tokenId = nextTokenId; tokenId <= lastTokenId; ++tokenId) {
            (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
            assertEq(recipient, minter);
            assertEq(value, (salePrice * tokenMock.royaltyFeeNumerator()) / tokenMock.FEE_DENOMINATOR());
        }
    }
}
