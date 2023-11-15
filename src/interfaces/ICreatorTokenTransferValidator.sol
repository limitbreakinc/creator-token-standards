// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "src/interfaces/IEOARegistry.sol";
import "src/interfaces/ITransferSecurityRegistry.sol";
import "src/interfaces/ITransferValidator.sol";

interface ICreatorTokenTransferValidator is ITransferSecurityRegistry, ITransferValidator, IEOARegistry {}