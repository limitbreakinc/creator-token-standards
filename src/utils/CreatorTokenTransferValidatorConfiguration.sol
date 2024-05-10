// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";

contract CreatorTokenTransferValidatorConfiguration is Ownable {

    error CreatorTokenTransferValidatorConfiguration__PermissionlessDeployNotAllowedYet();

    uint256 public immutable publicDeployTime;
    uint256 private nativeValueToCheckPauseState;

    constructor(address defaultOwner, uint256 publicDeployDelay) {
        // Allow owner time to deploy and configure custom settings that will
        // be set immutably in CreatorTokenTransferValidator while not 
        // preventing a permissionless deployment to alternate chains with
        // default settings. 
        publicDeployTime = block.timestamp + publicDeployDelay;

        _transferOwnership(defaultOwner);
    }

    function setNativeValueToCheckPauseState(uint256 _nativeValueToCheckPauseState) external onlyOwner {
        nativeValueToCheckPauseState = _nativeValueToCheckPauseState;
    }

    function getNativeValueToCheckPauseState(address deployer) external view returns(uint256 _nativeValueToCheckPauseState) {
        if (deployer != owner()) {
            if (block.timestamp < publicDeployTime) {
                revert CreatorTokenTransferValidatorConfiguration__PermissionlessDeployNotAllowedYet();
            }
        }

        _nativeValueToCheckPauseState = nativeValueToCheckPauseState;
    }
}