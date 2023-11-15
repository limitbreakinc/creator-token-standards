// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "src/interfaces/ICreatorTokenV2.sol";

interface ICreatorTokenWrapperERC20V2 is ICreatorTokenV2 {

    event Staked(address indexed account, uint256 amount);
    event Unstaked(address indexed account, uint256 amount);
    event StakerConstraintsSet(StakerConstraints stakerConstraints);

    function stake(uint256 amount) external payable;
    function unstake(uint256 amount) external payable;
    function canUnstake(uint256 amount) external view returns (bool);
    function getStakerConstraints() external view returns (StakerConstraints);
    function getWrappedCollectionAddress() external view returns (address);
}
