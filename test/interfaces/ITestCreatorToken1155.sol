// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "src/interfaces/ICreatorToken.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

interface ITestCreatorToken1155 is IERC1155, ICreatorToken {
    function DEFAULT_TRANSFER_VALIDATOR() external view returns (address);

    function mint(address, uint256, uint256) external;

    function setAutomaticApprovalOfTransfersFromValidator(bool autoApprove) external;
}
