// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "forge-std/Script.sol";
import "src/utils/CreatorTokenTransferValidator.sol";

contract DeployValidator is Script {
    function run() public {
        bytes32 saltValue = bytes32(vm.envUint("SALT_TRANSFER_VALIDATOR"));
        address expectedAddress = vm.envAddress("EXPECTED_VALIDATOR_ADDRESS");
        address validatorConfiguration = vm.envAddress("EXPECTED_VALIDATOR_CONFIGURATION_ADDRESS");
        address eoaRegistry = vm.envAddress("EXPECTED_EOA_REGISTRY_ADDRESS");
        string memory validatorName = vm.envString("VALIDATOR_NAME");
        string memory validatorVersion = vm.envString("VALIDATOR_VERSION");

        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_KEY");
        address defaultOwner = vm.envAddress("DEFAULT_OWNER_ADDRESS");
        
        vm.startBroadcast(deployerPrivateKey);
        address validator = address(new CreatorTokenTransferValidator{salt: saltValue}(defaultOwner, eoaRegistry, validatorName, validatorVersion, validatorConfiguration));
        vm.stopBroadcast();

        console.log("CreatorTokenTransferValidator: ", validator);

        if (expectedAddress != validator) {
            revert("Unexpected deploy address");
        }
    }
}