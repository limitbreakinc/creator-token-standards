// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./IEOARegistry.sol";
import "./ITransferSecurityRegistryV2.sol";
import "./ITransferValidator.sol";

interface ICreatorTokenTransferValidatorV2 is ITransferSecurityRegistryV2, ITransferValidator, IEOARegistry {}