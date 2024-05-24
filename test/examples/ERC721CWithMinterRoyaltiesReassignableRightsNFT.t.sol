// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../CreatorTokenNonfungible.t.sol";
import "../mocks/ERC20Mock.sol";
import "src/examples/erc721c/ERC721CWithReassignableMinterRoyalties.sol";
import "src/examples/adventure-erc721c/AdventureERC721CWithReassignableMinterRoyalties.sol";
import "src/programmable-royalties/helpers/RoyaltyRightsNFT.sol";

contract ERC721CWithMinterRoyaltiesReassignableRightsNFTTest is CreatorTokenNonfungibleTest {
    address public royaltyRightsNFTReference;
    ERC20Mock public coinMock;
    ERC721CWithReassignableMinterRoyalties public tokenMock;
    uint256 public constant DEFAULT_ROYALTY_FEE_NUMERATOR = 1000;

    address public defaultTokenCreator;

    function setUp() public virtual override {
        super.setUp();

        defaultTokenCreator = address(0x1);

        coinMock = new ERC20Mock(18);

        royaltyRightsNFTReference = address(new RoyaltyRightsNFT());

        vm.startPrank(defaultTokenCreator);
        tokenMock =
        new ERC721CWithReassignableMinterRoyalties(DEFAULT_ROYALTY_FEE_NUMERATOR, royaltyRightsNFTReference, "Test", "TEST");
        // TODO: tokenMock.setToCustomValidatorAndSecurityPolicy(address(validator), TransferSecurityLevels.One, 1, 0);
        vm.stopPrank();
    }

    function _deployNewToken(address creator) internal virtual override returns (ITestCreatorToken) {
        vm.prank(creator);
        return ITestCreatorToken(
            address(
                new ERC721CWithReassignableMinterRoyalties(DEFAULT_ROYALTY_FEE_NUMERATOR, royaltyRightsNFTReference, "Test", "TEST")
            )
        );
    }

    function _mintToken(address tokenAddress, address to, uint256 tokenId) internal virtual override {
        ERC721CWithReassignableMinterRoyalties(tokenAddress).mint(to, tokenId);
    }

    function _safeMintToken(address tokenAddress, address to, uint256 tokenId) internal virtual {
        ERC721CWithReassignableMinterRoyalties(tokenAddress).safeMint(to, tokenId);
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

    function testRevertsWhenFeeNumeratorExceedsSalesPrice(
        uint256 royaltyFeeNumerator,
        uint256 minterShares,
        uint256 creatorShares,
        address creator
    ) public {
        vm.assume(creator != address(0));
        vm.assume(minterShares > 0 && minterShares < 10000);
        vm.assume(creatorShares > 0 && creatorShares < 10000);
        vm.assume(royaltyFeeNumerator > tokenMock.FEE_DENOMINATOR());
        vm.expectRevert(
            MinterRoyaltiesReassignableRightsNFT
                .MinterRoyaltiesReassignableRightsNFT__RoyaltyFeeWillExceedSalePrice
                .selector
        );
        new ERC721CWithReassignableMinterRoyalties(royaltyFeeNumerator, royaltyRightsNFTReference, "Test", "TEST");
    }

    function testRevertsWhenMintingToZeroAddress(uint256 tokenId) public {
        vm.expectRevert(MinterRoyaltiesReassignableRightsNFT.MinterRoyaltiesReassignableRightsNFT__MinterCannotBeZeroAddress.selector);
        _mintToken(address(tokenMock), address(0), tokenId);
    }

    function testRoyaltyInfoForUnmintedTokenIds(uint256 tokenId, uint256 salePrice) public {
        vm.assume(salePrice < type(uint256).max / tokenMock.royaltyFeeNumerator());

        (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
        assertEq(recipient, address(0));
        assertEq(value, (salePrice * tokenMock.royaltyFeeNumerator()) / tokenMock.FEE_DENOMINATOR());
    }

    function testRoyaltyInfoForMintedTokenIds(address minter, uint256 tokenId, uint256 salePrice) public {
        vm.assume(minter != address(0));
        vm.assume(salePrice < type(uint256).max / tokenMock.royaltyFeeNumerator());

        _mintToken(address(tokenMock), minter, tokenId);

        (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
        assertEq(recipient, minter);
        assertEq(value, (salePrice * tokenMock.royaltyFeeNumerator()) / tokenMock.FEE_DENOMINATOR());

        assertEq(RoyaltyRightsNFT(address(tokenMock.royaltyRightsNFT())).ownerOf(tokenId), minter);
    }

    function testRoyaltyInfoForMintedTokenIdsAfterTransfer(
        address minter,
        address secondaryOwner,
        uint256 tokenId,
        uint256 salePrice
    ) public {
        vm.assume(minter != address(0));
        vm.assume(secondaryOwner != address(0));
        vm.assume(salePrice < type(uint256).max / tokenMock.royaltyFeeNumerator());

        _mintToken(address(tokenMock), minter, tokenId);

        vm.prank(minter);
        tokenMock.transferFrom(minter, secondaryOwner, tokenId);

        (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
        assertEq(recipient, minter);
        assertEq(value, (salePrice * tokenMock.royaltyFeeNumerator()) / tokenMock.FEE_DENOMINATOR());

        assertEq(RoyaltyRightsNFT(address(tokenMock.royaltyRightsNFT())).ownerOf(tokenId), minter);
    }

    function testRoyaltyRecipientResetsToAddressZeroAfterBurns(
        address minter,
        address secondaryOwner,
        uint256 tokenId,
        uint256 salePrice
    ) public {
        vm.assume(minter != address(0));
        vm.assume(secondaryOwner != address(0));
        vm.assume(salePrice < type(uint256).max / tokenMock.royaltyFeeNumerator());

        _mintToken(address(tokenMock), minter, tokenId);

        vm.prank(minter);
        tokenMock.transferFrom(minter, secondaryOwner, tokenId);

        vm.prank(secondaryOwner);
        tokenMock.burn(tokenId);

        (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
        assertEq(recipient, address(0));
        assertEq(value, (salePrice * tokenMock.royaltyFeeNumerator()) / tokenMock.FEE_DENOMINATOR());

        RoyaltyRightsNFT rightsNFT = RoyaltyRightsNFT(address(tokenMock.royaltyRightsNFT()));

        vm.expectRevert("ERC721: invalid token ID");
        address rightsOwner = rightsNFT.ownerOf(tokenId);
    }

    function testRevertsWhenRoyaltyRightsAreAlreadyInitialized() public {
        RoyaltyRightsNFT royaltyRights = RoyaltyRightsNFT(address(tokenMock.royaltyRightsNFT()));
        vm.expectRevert(RoyaltyRightsNFT.RoyaltyRightsNFT__CollectionAlreadyInitialized.selector);
        royaltyRights.initializeAndBindToCollection();
    }

    function testRevertsWhenRoyaltyRightsMintCalledByAccountOtherThanBoundCollection(address to, uint256 tokenId) public {
        RoyaltyRightsNFT royaltyRights = RoyaltyRightsNFT(address(tokenMock.royaltyRightsNFT()));
        vm.expectRevert(RoyaltyRightsNFT.RoyaltyRightsNFT__OnlyMintableFromCollection.selector);
        royaltyRights.mint(to, tokenId);
    }

    function testRevertsWhenRoyaltyRightsBurnCalledByAccountOtherThanBoundCollection(uint256 tokenId) public {
        RoyaltyRightsNFT royaltyRights = RoyaltyRightsNFT(address(tokenMock.royaltyRightsNFT()));
        vm.expectRevert(RoyaltyRightsNFT.RoyaltyRightsNFT__OnlyBurnableFromCollection.selector);
        royaltyRights.burn(tokenId);
    }

    function testRevertsIfTokenIdMintedAgain(address minter, uint256 tokenId, uint256 salePrice) public {
        vm.assume(minter != address(0));
        vm.assume(salePrice < type(uint256).max / tokenMock.royaltyFeeNumerator());

        _mintToken(address(tokenMock), minter, tokenId);

        vm.expectRevert("ERC721: token already minted");
        _mintToken(address(tokenMock), minter, tokenId);
    }

    function testBurnedTokenIdsCanBeReminted(
        address minter,
        address secondaryOwner,
        address reminter,
        uint256 tokenId,
        uint256 salePrice
    ) public {
        vm.assume(minter != address(0));
        vm.assume(secondaryOwner != address(0));
        vm.assume(reminter != address(0));
        vm.assume(salePrice < type(uint256).max / tokenMock.royaltyFeeNumerator());

        _mintToken(address(tokenMock), minter, tokenId);

        vm.prank(minter);
        tokenMock.transferFrom(minter, secondaryOwner, tokenId);

        vm.prank(secondaryOwner);
        tokenMock.burn(tokenId);

        _mintToken(address(tokenMock), reminter, tokenId);

        (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
        assertEq(recipient, reminter);
        assertEq(value, (salePrice * tokenMock.royaltyFeeNumerator()) / tokenMock.FEE_DENOMINATOR());

        assertEq(RoyaltyRightsNFT(address(tokenMock.royaltyRightsNFT())).ownerOf(tokenId), reminter);
    }

    function testRoyaltyInfoForSafeMintedTokenIds(address minter, uint256 tokenId, uint256 salePrice) public {
        vm.assume(minter != address(0));
        vm.assume(minter.code.length == 0);
        vm.assume(salePrice < type(uint256).max / tokenMock.royaltyFeeNumerator());

        _safeMintToken(address(tokenMock), minter, tokenId);

        (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
        assertEq(recipient, minter);
        assertEq(value, (salePrice * tokenMock.royaltyFeeNumerator()) / tokenMock.FEE_DENOMINATOR());

        assertEq(RoyaltyRightsNFT(address(tokenMock.royaltyRightsNFT())).ownerOf(tokenId), minter);
    }

    function testRoyaltyRightsNFTHolderGetsTheRoyalties(
        address minter,
        address rightsOwner,
        uint256 tokenId,
        uint256 salePrice
    ) public {
        vm.assume(minter != address(0));
        vm.assume(rightsOwner != address(0));
        vm.assume(salePrice < type(uint256).max / tokenMock.royaltyFeeNumerator());

        RoyaltyRightsNFT rightsNFT = RoyaltyRightsNFT(address(tokenMock.royaltyRightsNFT()));

        _mintToken(address(tokenMock), minter, tokenId);

        vm.prank(minter);
        rightsNFT.transferFrom(minter, rightsOwner, tokenId);

        (address recipient, uint256 value) = tokenMock.royaltyInfo(tokenId, salePrice);
        assertEq(recipient, rightsOwner);
        assertEq(value, (salePrice * tokenMock.royaltyFeeNumerator()) / tokenMock.FEE_DENOMINATOR());

        assertEq(RoyaltyRightsNFT(address(tokenMock.royaltyRightsNFT())).ownerOf(tokenId), rightsOwner);
    }

    function testRoyaltyRightsNameAndSymbol() public {
        RoyaltyRightsNFT royaltyRights = RoyaltyRightsNFT(address(tokenMock.royaltyRightsNFT()));
        assertEq(royaltyRights.name(), string(abi.encodePacked(tokenMock.name(), " Royalty Rights")));
        assertEq(royaltyRights.symbol(), string(abi.encodePacked(tokenMock.symbol(), "RR")));
    }

    function testRoyaltyRightsTokenURI(address to, uint256 tokenId) public {
        vm.assume(to != address(0));
        _mintToken(address(tokenMock), to, tokenId);

        RoyaltyRightsNFT royaltyRights = RoyaltyRightsNFT(address(tokenMock.royaltyRightsNFT()));
        assertEq(royaltyRights.tokenURI(tokenId), tokenMock.tokenURI(tokenId));
    }
}

contract AdventureERC721CWithReassignableMinterRoyaltiesTest is ERC721CWithMinterRoyaltiesReassignableRightsNFTTest {
    uint256 public constant MAX_SIMULTANEOUS_QUESTS = 10;

    function setUp() public virtual override {
        super.setUp();

        tokenMock = ERC721CWithReassignableMinterRoyalties(address(new AdventureERC721CWithReassignableMinterRoyalties(DEFAULT_ROYALTY_FEE_NUMERATOR, royaltyRightsNFTReference, MAX_SIMULTANEOUS_QUESTS, "Test", "TEST")));
        vm.prank(address(tokenMock));
        validator.setTransferSecurityLevelOfCollection(address(tokenMock), 1, false, false, false);
    }

    function _deployNewToken(address creator) internal virtual override returns (ITestCreatorToken) {
        vm.prank(creator);
        return ITestCreatorToken(
            address(new AdventureERC721CWithReassignableMinterRoyalties(DEFAULT_ROYALTY_FEE_NUMERATOR, royaltyRightsNFTReference, MAX_SIMULTANEOUS_QUESTS, "Test", "TEST"))
        );
    }

    function _mintToken(address tokenAddress, address to, uint256 tokenId) internal virtual override {
        AdventureERC721CWithReassignableMinterRoyalties(tokenAddress).mint(to, tokenId);
    }

    function _safeMintToken(address tokenAddress, address to, uint256 tokenId) internal virtual override {
        AdventureERC721CWithReassignableMinterRoyalties(tokenAddress).safeMint(to, tokenId);
    }

    // foundry cheat to exclude from test coverage
    function test() public {}
}