// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./ICreatorToken.sol";
import "../utils/TransferPolicy.sol";

interface ICreatorTokenWrapperERC721 is ICreatorToken {

    event Staked(uint256 indexed tokenId, address indexed account);
    event Unstaked(uint256 indexed tokenId, address indexed account);
    event StakerConstraintsSet(StakerConstraints stakerConstraints);

    function stake(uint256 tokenId) external payable;
    function stakeTo(uint256 tokenId, address to) external payable;
    function unstake(uint256 tokenId) external payable;
    function canUnstake(uint256 tokenId) external view returns (bool);
    function getStakerConstraints() external view returns (StakerConstraints);
    function getWrappedCollectionAddress() external view returns (address);
}
