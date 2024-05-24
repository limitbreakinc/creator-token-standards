// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "forge-std/Script.sol";
import "src/utils/EOARegistry.sol";

contract DeployEOARegistry is Script {
    function run() public {
        bytes32 saltValue = bytes32(vm.envUint("SALT_EOA_REGISTRY"));
        address expectedAddress = vm.envAddress("EXPECTED_EOA_REGISTRY_ADDRESS");
        
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_KEY");
        
        vm.startBroadcast(deployerPrivateKey);
        address registry = address(new EOARegistry{salt: saltValue}());
        vm.stopBroadcast();

        console.log("EOARegistry: ", registry);

        if (expectedAddress != registry) {
            revert("Unexpected deploy address");
        }
    }
}