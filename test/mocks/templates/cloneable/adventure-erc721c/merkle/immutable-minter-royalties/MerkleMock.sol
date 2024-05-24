// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "../../AdventureERC721CMetadataInitializable.sol";
import "src/minting/MerkleWhitelistMint.sol";
import "src/programmable-royalties/ImmutableMinterRoyalties.sol";

contract MerkleMock is
    AdventureERC721CMetadataInitializable,
    MerkleWhitelistMintInitializable,
    ImmutableMinterRoyaltiesInitializable
{
    constructor() ERC721("", "") {}

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(AdventureERC721CInitializable, ImmutableMinterRoyaltiesBase)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _mintToken(address to, uint256 tokenId) internal virtual override {
        _onMinted(to, tokenId);
        _mint(to, tokenId);
    }

    function _burn(uint256 tokenId) internal virtual override {
        super._burn(tokenId);
        _onBurned(tokenId);
    }
}
