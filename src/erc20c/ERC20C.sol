// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "../utils/AutomaticValidatorTransferApproval.sol";
import "../utils/CreatorTokenBase.sol";
import "../token/erc20/ERC20OpenZeppelin.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {TOKEN_TYPE_ERC20} from "@limitbreak/permit-c/Constants.sol";

/**
 * @title ERC20C
 * @author Limit Break, Inc.
 * @notice Extends OpenZeppelin's ERC20 implementation with Creator Token functionality, which
 *         allows the contract owner to update the transfer validation logic by managing a security policy in
 *         an external transfer validation security policy registry.  See {CreatorTokenTransferValidator}.
 */
abstract contract ERC20C is ERC165, ERC20OpenZeppelin, CreatorTokenBase, AutomaticValidatorTransferApproval {

    /**
     * @notice Overrides behavior of allowance such that if a spender is not explicitly approved,
     *         the contract owner can optionally auto-approve the 20-C transfer validator for transfers.
     */
    function allowance(address owner, address spender) public view virtual override returns (uint256 _allowance) {
        _allowance = super.allowance(owner, spender);

        if (_allowance == 0) {
            if (autoApproveTransfersFromValidator) {
                if (spender == address(getTransferValidator())) {
                    _allowance = type(uint256).max;
                }
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
        interfaceId == type(IERC20).interfaceId || 
        interfaceId == type(IERC20Metadata).interfaceId || 
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
        address from,
        address to,
        uint256 amount) internal virtual override {
        _validateBeforeTransfer(from, to, 0, amount);
    }

    /// @dev Ties the open-zeppelin _afterTokenTransfer hook to more granular transfer validation logic
    function _afterTokenTransfer(
        address from,
        address to,
        uint256 amount) internal virtual override {
        _validateAfterTransfer(from, to, 0, amount);
    }

    function _tokenType() internal pure override returns(uint16) {
        return uint16(TOKEN_TYPE_ERC20);
    }
}

/**
 * @title ERC20CInitializable
 * @author Limit Break, Inc.
 * @notice Initializable implementation of ERC20C to allow for EIP-1167 proxy clones.
 */
abstract contract ERC20CInitializable is ERC165, ERC20OpenZeppelinInitializable, CreatorTokenBase, AutomaticValidatorTransferApproval {

    function initializeERC20(string memory name_, string memory symbol_, uint8 decimals_) public override {
        super.initializeERC20(name_, symbol_, decimals_);

        _emitDefaultTransferValidator();
        _registerTokenType(getTransferValidator());
    }

    /**
     * @notice Overrides behavior of allowance such that if a spender is not explicitly approved,
     *         the contract owner can optionally auto-approve the 20-C transfer validator for transfers.
     */
    function allowance(address owner, address spender) public view virtual override returns (uint256 _allowance) {
        _allowance = super.allowance(owner, spender);

        if (_allowance == 0) {
            if (autoApproveTransfersFromValidator) {
                if (spender == address(getTransferValidator())) {
                    _allowance = type(uint256).max;
                }
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
        interfaceId == type(IERC20).interfaceId || 
        interfaceId == type(IERC20Metadata).interfaceId || 
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
        address from,
        address to,
        uint256 amount) internal virtual override {
        _validateBeforeTransfer(from, to, 0, amount);
    }

    /// @dev Ties the open-zeppelin _afterTokenTransfer hook to more granular transfer validation logic
    function _afterTokenTransfer(
        address from,
        address to,
        uint256 amount) internal virtual override {
        _validateAfterTransfer(from, to, 0, amount);
    }

    function _tokenType() internal pure override returns(uint16) {
        return uint16(TOKEN_TYPE_ERC20);
    }
}