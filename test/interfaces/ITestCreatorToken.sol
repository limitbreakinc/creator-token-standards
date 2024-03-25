// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "src/interfaces/ICreatorToken.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

interface ITestCreatorToken is IERC721, ICreatorToken {
    function DEFAULT_TRANSFER_VALIDATOR() external view returns (address);
    
    function mint(address, uint256) external;
    
    function setAutomaticApprovalOfTransfersFromValidator(bool autoApprove) external;
}
