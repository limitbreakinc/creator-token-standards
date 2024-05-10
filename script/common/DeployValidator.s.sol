// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "forge-std/Script.sol";
import "src/utils/CreatorTokenTransferValidator.sol";

contract DeployValidator is Script {
    function run() public {
        bytes32 saltValue = bytes32(vm.envUint("SALT_TRANSFER_VALIDATOR_V2"));
        address expectedAddress = vm.envAddress("EXPECTED_VALIDATOR_ADDRESS");
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_KEY");
        address defaultOwner = vm.envAddress("DEFAULT_OWNER_ADDRESS");
        
        vm.startBroadcast(deployerPrivateKey);
        // TODO: Update validator configuration deployment
        address validatorConfiguration = address(new CreatorTokenTransferValidatorConfiguration{salt: saltValue}(defaultOwner, 0));
        address validator = address(new CreatorTokenTransferValidator(defaultOwner, address(0), "", "", validatorConfiguration));
        vm.stopBroadcast();

        console.log("CreatorTokenTransferValidatorV2: ", validator);

        if (expectedAddress != validator) {
            revert("Unexpected deploy address");
        }
    }
}