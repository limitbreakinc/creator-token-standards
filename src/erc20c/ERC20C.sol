// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "../utils/CreatorTokenBase.sol";
import "../token/erc20/ERC20OpenZeppelin.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";

/**
 * @title ERC20C
 * @author Limit Break, Inc.
 * @notice Extends OpenZeppelin's ERC20 implementation with Creator Token functionality, which
 *         allows the contract owner to update the transfer validation logic by managing a security policy in
 *         an external transfer validation security policy registry.  See {CreatorTokenTransferValidator}.
 */
abstract contract ERC20C is ERC165, ERC20OpenZeppelin, CreatorTokenBase {

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return 
        interfaceId == type(IERC20).interfaceId || 
        interfaceId == type(IERC20Metadata).interfaceId || 
        interfaceId == type(ICreatorToken).interfaceId || 
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
}

/**
 * @title ERC20CInitializable
 * @author Limit Break, Inc.
 * @notice Initializable implementation of ERC20C to allow for EIP-1167 proxy clones.
 */
abstract contract ERC20CInitializable is ERC165, ERC20OpenZeppelinInitializable, CreatorTokenBase {

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return 
        interfaceId == type(IERC20).interfaceId || 
        interfaceId == type(IERC20Metadata).interfaceId || 
        interfaceId == type(ICreatorToken).interfaceId || 
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
}