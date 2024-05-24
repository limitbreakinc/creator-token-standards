// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract Helpers is Test {
    function setUp() public virtual {}

    function _sanitizeAddress(address addr) internal view virtual {
        _sanitizeAddress(addr, new address[](0));
    }

    function _sanitizeAddress(address addr, address[] memory exclusionList) internal view {
        vm.assume(addr.code.length == 0);
        vm.assume(uint160(addr) > 0xFF);
        vm.assume(addr != address(0));
        vm.assume(addr != address(0x000000000000000000636F6e736F6c652e6c6f67));
        vm.assume(addr != address(0xDDc10602782af652bB913f7bdE1fD82981Db7dd9));

        for (uint256 i = 0; i < exclusionList.length; ++i) {
            vm.assume(addr != exclusionList[i]);
        }
    }
}