// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "test/interfaces/IOwnableInitializable.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";

contract ClonerMock {
    error InitializationArgumentInvalid(uint256 arrayIndex);

    constructor() {}

    function cloneContract(
        address referenceContract,
        address contractOwner,
        bytes4[] calldata initializationSelectors,
        bytes[] calldata initializationArgs
    ) external returns (address) {
        bytes32 salt = keccak256(abi.encode(blockhash(block.number - 1)));
        address clone = Clones.predictDeterministicAddress(referenceContract, salt, address(this));
        bool codeEmpty;
        while (true) {
            assembly {
                codeEmpty := iszero(extcodesize(clone))
            }
            if (!codeEmpty) {
                salt = keccak256(abi.encode(salt));
                clone = Clones.predictDeterministicAddress(referenceContract, salt, address(this));
                continue;
            }
            break;
        }
        Clones.cloneDeterministic(referenceContract, salt);

        IOwnableInitializer(clone).initializeOwner(address(this));

        for (uint256 i = 0; i < initializationSelectors.length;) {
            (bool success,) = clone.call(abi.encodePacked(initializationSelectors[i], initializationArgs[i]));

            if (!success) {
                revert InitializationArgumentInvalid(i);
            }

            unchecked {
                ++i;
            }
        }

        IOwnableInitializer(clone).transferOwnership(contractOwner);

        return clone;
    }
}
