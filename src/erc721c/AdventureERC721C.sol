// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "../utils/AutomaticValidatorTransferApproval.sol";
import "../utils/CreatorTokenBase.sol";
import "../adventures/AdventureERC721.sol";
import {TOKEN_TYPE_ERC721} from "@limitbreak/permit-c/Constants.sol";

/**
 * @title AdventureERC721C
 * @author Limit Break, Inc.
 * @notice Extends Limit Break's AdventureERC721 implementation with Creator Token functionality, which
 *         allows the contract owner to update the transfer validation logic by managing a security policy in
 *         an external transfer validation security policy registry.  See {CreatorTokenTransferValidator}.
 */
abstract contract AdventureERC721C is AdventureERC721, CreatorTokenBase, AutomaticValidatorTransferApproval {

    /**
     * @notice Overrides behavior of isApprovedFor all such that if an operator is not explicitly approved
     *         for all, the contract owner can optionally auto-approve the 721-C transfer validator for transfers.
     */
    function isApprovedForAll(address owner, address operator) public view virtual override returns (bool isApproved) {
        isApproved = super.isApprovedForAll(owner, operator);

        if (!isApproved) {
            if (autoApproveTransfersFromValidator) {
                isApproved = operator == address(getTransferValidator());
            }
        }
    }

    /**
     * @notice Indicates whether the contract implements the specified interface.
     * @dev Overrides supportsInterface in ERC165.
     * @param interfaceId The interface id
     * @return true if the contract implements the specified interface, false otherwise
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return 
        interfaceId == type(ICreatorToken).interfaceId || 
        interfaceId == type(ICreatorTokenLegacy).interfaceId || 
        super.supportsInterface(interfaceId);
    }

    /**
     * @notice Returns the function selector for the transfer validator's validation function to be called 
     * @notice for transaction simulation. 
     */
    function getTransferValidationFunction() external pure returns (bytes4 functionSignature, bool isViewFunction) {
        functionSignature = bytes4(keccak256("validateTransfer(address,address,address,uint256)"));
        isViewFunction = true;
    }

    /// @dev Ties the adventure erc721 _beforeTokenTransfer hook to more granular transfer validation logic
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 firstTokenId,
        uint256 batchSize) internal virtual override {

        uint256 tokenId;
        for (uint256 i = 0; i < batchSize;) {
            tokenId = firstTokenId + i;
            if(blockingQuestCounts[tokenId] > 0) {
                revert AdventureERC721__AnActiveQuestIsPreventingTransfers();
            }

            if(transferType == TRANSFERRING_VIA_ERC721) {
                _validateBeforeTransfer(from, to, tokenId);
            }

            unchecked {
                ++i;
            }
        }
    }

    /// @dev Ties the adventure erc721 _afterTokenTransfer hook to more granular transfer validation logic
    function _afterTokenTransfer(
        address from,
        address to,
        uint256 firstTokenId,
        uint256 batchSize) internal virtual override {
        for (uint256 i = 0; i < batchSize;) {
            _validateAfterTransfer(from, to, firstTokenId + i);
            unchecked {
                ++i;
            }
        }
    }

    function _tokenType() internal pure override returns(uint16) {
        return uint16(TOKEN_TYPE_ERC721);
    }
}


/**
 * @title AdventureERC721CInitializable
 * @author Limit Break, Inc.
 * @notice Initializable implementation of the AdventureERC721C contract to allow for EIP-1167 clones.
 */
abstract contract AdventureERC721CInitializable is AdventureERC721Initializable, CreatorTokenBase, AutomaticValidatorTransferApproval {

    function initializeERC721(string memory name_, string memory symbol_) public override {
        super.initializeERC721(name_, symbol_);

        _emitDefaultTransferValidator();
        _registerTokenType(getTransferValidator());
    }

    /**
     * @notice Overrides behavior of isApprovedFor all such that if an operator is not explicitly approved
     *         for all, the contract owner can optionally auto-approve the 721-C transfer validator for transfers.
     */
    function isApprovedForAll(address owner, address operator) public view virtual override returns (bool isApproved) {
        isApproved = super.isApprovedForAll(owner, operator);

        if (!isApproved) {
            if (autoApproveTransfersFromValidator) {
                isApproved = operator == address(getTransferValidator());
            }
        }
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return 
        interfaceId == type(ICreatorToken).interfaceId || 
        interfaceId == type(ICreatorTokenLegacy).interfaceId || 
        super.supportsInterface(interfaceId);
    }

    /**
     * @notice Returns the function selector for the transfer validator's validation function to be called 
     * @notice for transaction simulation. 
     */
    function getTransferValidationFunction() external pure returns (bytes4 functionSignature, bool isViewFunction) {
        functionSignature = bytes4(keccak256("validateTransfer(address,address,address,uint256)"));
        isViewFunction = true;
    }

    /// @dev Ties the adventure erc721 _beforeTokenTransfer hook to more granular transfer validation logic
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 firstTokenId,
        uint256 batchSize) internal virtual override {

        uint256 tokenId;
        for (uint256 i = 0; i < batchSize;) {
            tokenId = firstTokenId + i;
            if(blockingQuestCounts[tokenId] > 0) {
                revert AdventureERC721__AnActiveQuestIsPreventingTransfers();
            }

            if(transferType == TRANSFERRING_VIA_ERC721) {
                _validateBeforeTransfer(from, to, tokenId);
            }

            unchecked {
                ++i;
            }
        }
    }

    /// @dev Ties the adventure erc721 _afterTokenTransfer hook to more granular transfer validation logic
    function _afterTokenTransfer(
        address from,
        address to,
        uint256 firstTokenId,
        uint256 batchSize) internal virtual override {
        for (uint256 i = 0; i < batchSize;) {
            _validateAfterTransfer(from, to, firstTokenId + i);
            unchecked {
                ++i;
            }
        }
    }

    function _tokenType() internal pure override returns(uint16) {
        return uint16(TOKEN_TYPE_ERC721);
    }
}