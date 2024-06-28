// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

abstract contract TransferHooks {
    
    /*************************************************************************/
    /*                      Transfers Without Amounts                        */
    /*************************************************************************/

    /// @dev Optional validation hook that fires before a mint
    function _validateMint(address caller, address to, uint256 tokenId, uint256 value) internal virtual {}

    /// @dev Optional validation hook that fires before a burn
    function _validateBurn(address caller, address from, uint256 tokenId, uint256 value) internal virtual {}

    /// @dev Optional validation hook that fires before a transfer
    function _validateTransfer(address caller, address from, address to, uint256 tokenId, uint256 value) internal virtual {}

    /*************************************************************************/
    /*                         Transfers With Amounts                        */
    /*************************************************************************/

    /// @dev Optional validation hook that fires before a mint
    function _validateMint(address caller, address to, uint256 tokenId, uint256 amount, uint256 value) internal virtual {}

    /// @dev Optional validation hook that fires before a burn
    function _validateBurn(address caller, address from, uint256 tokenId, uint256 amount, uint256 value) internal virtual {}

    /// @dev Optional validation hook that fires before a transfer
    function _validateTransfer(address caller, address from, address to, uint256 tokenId, uint256 amount, uint256 value) internal virtual {}
}
