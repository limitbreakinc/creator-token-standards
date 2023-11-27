// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "src/utils/CreatorTokenBaseV2.sol";
import "src/token/erc20/ERC20OpenZeppelin.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";

/**
 * @title ERC20C
 * @author Limit Break, Inc.
 * @notice Extends OpenZeppelin's ERC20 implementation with Creator Token functionality, which
 *         allows the contract owner to update the transfer validation logic by managing a security policy in
 *         an external transfer validation security policy registry.  See {CreatorTokenTransferValidator}.
 */
abstract contract ERC20C is ERC165, ERC20OpenZeppelin, CreatorTokenBaseV2 {

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return 
        interfaceId == type(IERC20).interfaceId || 
        interfaceId == type(IERC20Metadata).interfaceId || 
        interfaceId == type(ICreatorToken).interfaceId || 
        super.supportsInterface(interfaceId);
    }

    /// @dev Ties the open-zeppelin _beforeTokenTransfer hook to more granular transfer validation logic
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 /*amount*/) internal virtual override {
        _validateBeforeTransfer(from, to, 0);
    }

    /// @dev Ties the open-zeppelin _afterTokenTransfer hook to more granular transfer validation logic
    function _afterTokenTransfer(
        address from,
        address to,
        uint256 /*amount*/) internal virtual override {
        _validateAfterTransfer(from, to, 0);
    }
}

/**
 * @title ERC20CInitializable
 * @author Limit Break, Inc.
 * @notice Initializable implementation of ERC20C to allow for EIP-1167 proxy clones.
 */
abstract contract ERC20CInitializable is ERC165, ERC20OpenZeppelinInitializable, CreatorTokenBaseV2 {

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return 
        interfaceId == type(IERC20).interfaceId || 
        interfaceId == type(IERC20Metadata).interfaceId || 
        interfaceId == type(ICreatorToken).interfaceId || 
        super.supportsInterface(interfaceId);
    }

    /// @dev Ties the open-zeppelin _beforeTokenTransfer hook to more granular transfer validation logic
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 /*amount*/) internal virtual override {
        _validateBeforeTransfer(from, to, 0);
    }

    /// @dev Ties the open-zeppelin _afterTokenTransfer hook to more granular transfer validation logic
    function _afterTokenTransfer(
        address from,
        address to,
        uint256 /*amount*/) internal virtual override {
        _validateAfterTransfer(from, to, 0);
    }
}