// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "src/access/OwnableInitializable.sol";
import "src/erc721c/AdventureERC721C.sol";
import "src/token/erc721/MetadataURI.sol";

abstract contract AdventureERC721CMetadataInitializable is
    OwnableInitializable,
    MetadataURIInitializable,
    AdventureERC721CInitializable
{
    using Strings for uint256;

    error AdventureFreeNFT__NonexistentToken();

    /// @notice Returns tokenURI if baseURI is set
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        if (!_exists(tokenId)) {
            revert AdventureFreeNFT__NonexistentToken();
        }

        string memory baseURI = _baseURI();
        return bytes(baseURI).length > 0 ? string(abi.encodePacked(baseURI, tokenId.toString(), suffixURI)) : "";
    }

    /// @dev Required to return baseTokenURI for tokenURI
    function _baseURI() internal view virtual override returns (string memory) {
        return baseTokenURI;
    }
}
