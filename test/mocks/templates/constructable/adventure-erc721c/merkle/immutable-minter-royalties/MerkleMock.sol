// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "../../AdventureERC721CMetadata.sol";
import "src/minting/MerkleWhitelistMint.sol";
import "src/programmable-royalties/ImmutableMinterRoyalties.sol";

contract MerkleMock is AdventureERC721CMetadata, MerkleWhitelistMint, ImmutableMinterRoyalties {
    constructor(
        string memory name_,
        string memory symbol_,
        uint256 maxSimultaneousQuests_,
        uint256 maxSupply_,
        uint256 maxOwnerMints_,
        uint256 maxMerkleMints_,
        uint256 permittedNumberOfMerkleRootChanges_,
        uint256 royaltyFeeNumerator_
    )
        AdventureERC721CMetadata(name_, symbol_, maxSimultaneousQuests_)
        MaxSupply(maxSupply_, maxOwnerMints_)
        MerkleWhitelistMint(maxMerkleMints_, permittedNumberOfMerkleRootChanges_)
        ImmutableMinterRoyalties(royaltyFeeNumerator_)
    {}

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(AdventureERC721C, ImmutableMinterRoyaltiesBase)
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
