// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "src/interfaces/ICreatorToken.sol";

interface ITestCreatorToken is ICreatorToken {
    function DEFAULT_TRANSFER_VALIDATOR() external view returns (address);
    
    function mint(address, uint256) external;
    function mint(address, uint256, uint256) external;
    
    function setAutomaticApprovalOfTransfersFromValidator(bool autoApprove) external;

    function setApprovalForAll(address operator, bool _approved) external;
    function isApprovedForAll(address owner, address operator) external view returns (bool);

    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
