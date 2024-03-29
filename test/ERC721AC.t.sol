// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./mocks/ERC721ACMock.sol";
import "./CreatorToken.t.sol";

contract ERC721CTest is CreatorTokenTest {
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
}