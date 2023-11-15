// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "src/interfaces/IEOARegistry.sol";
import "src/interfaces/ITransferSecurityRegistryV2.sol";
import "src/interfaces/ITransferValidator.sol";

interface ICreatorTokenTransferValidatorV2 is ITransferSecurityRegistryV2, ITransferValidator, IEOARegistry {}