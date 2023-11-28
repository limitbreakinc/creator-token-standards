// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "forge-std/Script.sol";
import "src/utils/CreatorTokenTransferValidatorV2.sol";

contract DeployV2 is Script {
    function run() public {
        bytes32 saltValue = bytes32(vm.envUint("SALT_TRANSFER_VALIDATOR_V2"));
        address expectedValidatorAddress = vm.envAddress("EXPECTED_VALIDATOR_ADDRESS_V2");

        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_KEY");
        vm.startBroadcast(deployerPrivateKey);
        
        CreatorTokenTransferValidatorV2 validator = 
            new CreatorTokenTransferValidatorV2{salt: saltValue}(vm.addr(deployerPrivateKey));

        vm.stopBroadcast();

        console.log("Creator Token Transfer Validator V2: ", address(validator));

        if (expectedValidatorAddress != address(validator)) {
            revert("Unexpected validator address");
        }
    }
}