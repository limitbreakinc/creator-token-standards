// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "src/access/OwnableBasic.sol";
import "src/access/OwnableInitializable.sol";
import "src/erc721c/ERC721C.sol";
import "src/minting/ClaimableHolderMint.sol";

contract ClaimableHolderMintMock is ERC721C, ClaimableHolderMint, OwnableBasic {
    constructor(
        address[] memory rootCollections_,
        uint256[] memory rootCollectionMaxSupplies_,
        uint256[] memory tokensPerClaimArray_,
        uint256 maxSupply_,
        uint256 maxOwnerMints_
    )
        ERC721OpenZeppelin("ClaimableHolderMintMock", "CHM")
        ClaimableHolderMint(rootCollections_, rootCollectionMaxSupplies_, tokensPerClaimArray_)
        MaxSupply(maxSupply_, maxOwnerMints_)
    {}

    function _mintToken(address to, uint256 tokenId) internal virtual override {
        _mint(to, tokenId);
    }
}

contract ClaimableHolderMintInitializableMock is
    ERC721CInitializable,
    ClaimableHolderMintInitializable,
    OwnableInitializable
{
    constructor() ERC721("", "") {}

    function _mintToken(address to, uint256 tokenId) internal virtual override {
        _mint(to, tokenId);
    }
}
