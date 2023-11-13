// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "src/interfaces/ICreatorTokenV2.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

interface ITestCreatorToken is IERC721, ICreatorTokenV2 {
    function DEFAULT_TRANSFER_VALIDATOR() external view returns (address);
    
    function mint(address, uint256) external;
    function setTransferValidator(address transferValidator_) external;
    function setToDefaultSecurityPolicy() external;

    function setToCustomValidatorAndSecurityPolicy(
        address validator,
        TransferSecurityLevels level,
        uint120 operatorWhitelistId,
        uint120 permittedContractReceiversAllowlistId
    ) external;

    function setToCustomValidatorAndSecurityPolicy(
        address validator,
        TransferSecurityLevels level,
        uint120 listId
    ) external;

    function setToCustomSecurityPolicy(
        TransferSecurityLevels level,
        uint120 listId
    ) external;
}
