// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./mocks/ERC721ACMock.sol";
import "./CreatorTokenNonfungible.t.sol";

contract ERC721CTest is CreatorTokenNonfungibleTest {
    function setUp() public virtual override {
        super.setUp();
    }

    function _deployNewToken(address creator) internal virtual override returns (ITestCreatorToken) {
        vm.prank(creator);
        return ITestCreatorToken(address(new ERC721ACMock()));
    }

    function _mintToken(address tokenAddress, address to, uint256 tokenId) internal virtual override {
        ERC721ACMock(tokenAddress).mint(to, tokenId);
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

    function testTransferValidatorTokenTypeIsSet() public {
        ITestCreatorToken tokenMock = _deployNewToken(address(this));
        CollectionSecurityPolicyV3 memory securityPolicy = validator.getCollectionSecurityPolicy(address(tokenMock));
        assertEq(securityPolicy.tokenType, TOKEN_TYPE_ERC721);
    }
}