// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "../utils/AutomaticValidatorTransferApproval.sol";
import "../utils/CreatorTokenBase.sol";
import "../token/erc1155/ERC1155OpenZeppelin.sol";
import {TOKEN_TYPE_ERC1155} from "@limitbreak/permit-c/Constants.sol";

/**
 * @title ERC1155C
 * @author Limit Break, Inc.
 * @notice Extends OpenZeppelin's ERC1155 implementation with Creator Token functionality, which
 *         allows the contract owner to update the transfer validation logic by managing a security policy in
 *         an external transfer validation security policy registry.  See {CreatorTokenTransferValidator}.
 */
abstract contract ERC1155C is ERC1155OpenZeppelin, CreatorTokenBase, AutomaticValidatorTransferApproval {
    
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
        functionSignature = bytes4(keccak256("validateTransfer(address,address,address,uint256,uint256)"));
        isViewFunction = false;
    }

    /// @dev Ties the open-zeppelin _beforeTokenTransfer hook to more granular transfer validation logic
    function _beforeTokenTransfer(
        address /*operator*/,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory /*data*/
    ) internal virtual override {
        uint256 idsArrayLength = ids.length;
        for (uint256 i = 0; i < idsArrayLength;) {
            _validateBeforeTransfer(from, to, ids[i], amounts[i]);

            unchecked {
                ++i;
            }
        }
    }

    /// @dev Ties the open-zeppelin _afterTokenTransfer hook to more granular transfer validation logic
    function _afterTokenTransfer(
        address /*operator*/,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory /*data*/
    ) internal virtual override {
        uint256 idsArrayLength = ids.length;
        for (uint256 i = 0; i < idsArrayLength;) {
            _validateAfterTransfer(from, to, ids[i], amounts[i]);

            unchecked {
                ++i;
            }
        }
    }

    function _tokenType() internal pure override returns(uint16) {
        return uint16(TOKEN_TYPE_ERC1155);
    }
}

/**
 * @title ERC1155CInitializable
 * @author Limit Break, Inc.
 * @notice Initializable implementation of ERC1155C to allow for EIP-1167 proxy clones.
 */
abstract contract ERC1155CInitializable is ERC1155OpenZeppelinInitializable, CreatorTokenBase, AutomaticValidatorTransferApproval {

    function initializeERC1155(string memory uri_) public override {
        super.initializeERC1155(uri_);

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
        functionSignature = bytes4(keccak256("validateTransfer(address,address,address,uint256,uint256)"));
        isViewFunction = false;
    }

    /// @dev Ties the open-zeppelin _beforeTokenTransfer hook to more granular transfer validation logic
    function _beforeTokenTransfer(
        address /*operator*/,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory /*data*/
    ) internal virtual override {
        uint256 idsArrayLength = ids.length;
        for (uint256 i = 0; i < idsArrayLength;) {
            _validateBeforeTransfer(from, to, ids[i], amounts[i]);

            unchecked {
                ++i;
            }
        }
    }

    /// @dev Ties the open-zeppelin _afterTokenTransfer hook to more granular transfer validation logic
    function _afterTokenTransfer(
        address /*operator*/,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory /*data*/
    ) internal virtual override {
        uint256 idsArrayLength = ids.length;
        for (uint256 i = 0; i < idsArrayLength;) {
            _validateAfterTransfer(from, to, ids[i], amounts[i]);

            unchecked {
                ++i;
            }
        }
    }

    function _tokenType() internal pure override returns(uint16) {
        return uint16(TOKEN_TYPE_ERC1155);
    }
}
