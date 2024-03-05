// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./IEOARegistry.sol";
import "./ITransferSecurityRegistryV3.sol";
import "./ITransferValidator.sol";

interface ICreatorTokenTransferValidatorV3 is ITransferSecurityRegistryV3, ITransferValidator, IEOARegistry {}