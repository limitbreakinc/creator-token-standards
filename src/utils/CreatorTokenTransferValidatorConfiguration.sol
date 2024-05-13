// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";

contract CreatorTokenTransferValidatorConfiguration is Ownable {

    error CreatorTokenTransferValidatorConfiguration__ConfigurationNotInitialized();

    bool configurationInitialized;
    uint256 private nativeValueToCheckPauseState;

    constructor(address defaultOwner) {
        _transferOwnership(defaultOwner);
    }

    function setNativeValueToCheckPauseState(uint256 _nativeValueToCheckPauseState) external onlyOwner {
        nativeValueToCheckPauseState = _nativeValueToCheckPauseState;
        configurationInitialized = true;
    }

    function getNativeValueToCheckPauseState() external view returns(uint256 _nativeValueToCheckPauseState) {
        if (!configurationInitialized) {
            revert CreatorTokenTransferValidatorConfiguration__ConfigurationNotInitialized();
        }

        _nativeValueToCheckPauseState = nativeValueToCheckPauseState;
    }
}