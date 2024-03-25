// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

interface ICreatorToken {
    event TransferValidatorUpdated(address oldValidator, address newValidator);
    function getTransferValidator() external view returns (address validator);
    function setTransferValidator(address validator) external;
}
