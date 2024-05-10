// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

contract Events {
    event CreatedList(uint256 indexed id, string name);
    event AppliedListToCollection(address indexed collection, uint120 indexed id);
    event ReassignedListOwnership(uint256 indexed id, address indexed newOwner);
    event AccountFrozenForCollection(address indexed collection, address indexed account);
    event AccountUnfrozenForCollection(address indexed collection, address indexed account);
    event AddedAccountToList(uint8 indexed kind, uint256 indexed id, address indexed account);
    event AddedCodeHashToList(uint8 indexed kind, uint256 indexed id, bytes32 indexed codehash);
    event RemovedAccountFromList(uint8 indexed kind, uint256 indexed id, address indexed account);
    event RemovedCodeHashFromList(uint8 indexed kind, uint256 indexed id, bytes32 indexed codehash);
    event SetTransferSecurityLevel(address indexed collection, uint8 level);
    event SetAuthorizationModeEnabled(address indexed collection, bool enabled, bool authorizersCannotSetWildcardOperators);
    event SetAccountFreezingModeEnabled(address indexed collection, bool enabled);
}