// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

interface ICreatorToken {
    event TransferValidatorUpdated(address oldValidator, address newValidator);
    function getTransferValidator() external view returns (address validator);
    function isTransferAllowed(address caller, address from, address to) external view returns (bool);
    function isTransferAllowed(address caller, address from, address to, uint256 tokenId) external view returns (bool);
    function setTransferValidator(address validator) external;
}
