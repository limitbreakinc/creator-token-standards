// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "forge-std/Script.sol";
import "src/utils/CreatorTokenTransferValidator.sol";

contract DeployValidatorConfiguration is Script {
    function run() public {
        bytes32 saltValue = bytes32(vm.envUint("SALT_TRANSFER_VALIDATOR_CONFIGURATION"));
        address expectedAddress = vm.envAddress("EXPECTED_VALIDATOR_CONFIGURATION_ADDRESS");

        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_KEY");
        address defaultOwner = vm.envAddress("DEFAULT_OWNER_ADDRESS");
        
        vm.startBroadcast(deployerPrivateKey);
        address validatorConfiguration = address(new CreatorTokenTransferValidatorConfiguration{salt: saltValue}(defaultOwner));
        vm.stopBroadcast();

        console.log("CreatorTokenTransferValidatorConfiguration: ", validatorConfiguration);

        if (expectedAddress != validatorConfiguration) {
            revert("Unexpected deploy address");
        }
    }
}