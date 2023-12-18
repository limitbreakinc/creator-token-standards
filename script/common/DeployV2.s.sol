// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "forge-std/Script.sol";
import "src/utils/CreatorTokenTransferValidatorV2.sol";

contract DeployV2 is Script {
    function run() public {
        bytes32 saltValue = bytes32(vm.envUint("SALT_TRANSFER_VALIDATOR_V2"));
        address expectedAddress = vm.envAddress("EXPECTED_VALIDATOR_ADDRESS_V2");
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_KEY");
        address defaultOwner = vm.envAddress("DEFAULT_OWNER_ADDRESS");
        
        vm.startBroadcast(deployerPrivateKey);
        address validator = address(new CreatorTokenTransferValidatorV2{salt: saltValue}(defaultOwner));
        vm.stopBroadcast();

        console.log("CreatorTokenTransferValidatorV2: ", validator);

        if (expectedAddress != validator) {
            revert("Unexpected deploy address");
        }
    }
}